# 🔐 Security-Focused Test Suite - Implementation Summary

## Overview

This document summarizes the security-focused test suite created for Meow Decoder v1.0 and expanded in February 2026.

**Current stats (February 2026):** 59 active test files (52 archived to `tests/_archive/`), 1541+ active Python tests + 465 Rust tests.
**Migration status:** All production crypto routes through Rust backend (`meow_crypto_rs`).
**Surface area minimization (2026-02-18):** 45 non-production source modules archived to `meow_decoder/_archive/`; 52 test files covering only archived modules moved to `tests/_archive/`. See `docs/SURFACE_AREA_MINIMIZATION.md` for full report.
**Audit (2026-02-17):** Post-Rust migration test audit complete. See `todo-12.md` for 12 remaining `from cryptography` test fixture imports.

### Consolidation History (February 2026)

**Phase 0:** Merged 14 secondary test files into primary module-specific files; decomposed 2 large omnibus coverage-boost files into 20+ module-specific targets; resolved 10 class name collisions with `Boost` suffix renames.

**Phase 1 (1-to-1 mapping):** Merged all 25 `*_comprehensive.py` files into their corresponding `test_<module>.py` counterparts:
- 16 identical duplicates deleted (content already in the 1-to-1 file)
- 8 files appended in full (unique tests added to existing file)
- 1 file (schrodinger) merged with conflict resolution (duplicate class skipped, unique method added)
- Every `meow_decoder/*.py` module now has a matching `tests/test_*.py` — zero gaps

## Test Files (Current)

### TIER 1: Crypto-Critical Tests (95-100% coverage target)

| File | Tests | Purpose |
|------|-------|---------|
| `test_crypto.py` | 205 | Core AES-256-GCM encryption, KDF, AAD construction, manifest bounds, timing harness |
| `test_crypto_backend.py` | 105 | Rust crypto backend bindings |
| `test_constant_time.py` | 45 | Constant-time comparison, secure memset, timing consistency |
| `test_frame_mac.py` | 11 | Frame MAC authentication, key derivation, pack/unpack |
| `test_fountain.py` | 12 | Fountain code encoding/decoding, droplet generation |
| `test_golden_vectors.py` | 30 | Frozen golden vectors: Argon2id, HKDF, AES-GCM, HMAC, SHA-256, AAD, ratchet, pipeline |
| `test_ratchet.py` | 142 | MSR v1 symmetric ratchet: domain separation, forward secrecy, replay, commitment tags |

> **Archived from TIER 1:** `test_crypto_enhanced.py`, `test_streaming_crypto.py`, `test_crypto_enforcement.py` — moved to `tests/_archive/`

### TIER 2: Core Pipeline Tests (90%+ coverage target)

| File | Tests | Purpose |
|------|-------|---------|
| `test_encode.py` | 63 | Encoding pipeline, QR generation, frame assembly |
| `test_decode_gif.py` | 49 | GIF decoding, frame extraction, QR reading |
| `test_gif_handler.py` | 13 | GIF creation, frame handling, size validation |
| `test_qr_code.py` | 16 | QR code generation and reading |
| `test_config.py` | 17 | EncodingConfig, MeowConfig, DuressConfig |
| `test_metadata_obfuscation.py` | 17 | Length padding, corruption detection |
| `test_e2e_crypto_fountain.py` | 23 | E2E pipeline: encrypt→fountain→corrupt/reorder/drop→decode→decrypt |
| `test_e2e_ratchet_pipeline.py` | 23 | E2E pipeline with per-frame ratchet under loss/reorder |
| `test_e2e_gif_ratchet.py` | — | E2E GIF + ratchet integration |
| `test_fountain_montecarlo.py` | 10 | Monte Carlo statistical reliability of LT codes under frame loss |

> **Archived from TIER 2:** `test_spec_v12.py`, `test_coverage_gaps_phase1.py` — moved to `tests/_archive/`

### TIER 3: Security Features Tests

| File | Tests | Purpose |
|------|-------|---------|
| `test_security.py` | 20 | Tamper detection, auth tag verification |
| `test_adversarial.py` | 20 | Hostile input handling, corruption resilience |
| `test_sidechannel.py` | 11 | Side-channel resistance |
| `test_invariants.py` | 11 | Security invariant checks |
| `test_x25519_forward_secrecy.py` | 42 | X25519 key derivation, ephemeral keys, hybrid keys |
| `test_duress_mode.py` | 57 | Duress mode, decoy data, timing equalization |
| `test_timelock_duress.py` | 32 | Timelock puzzles, countdown duress, deadman switch |
| `test_pq_crypto_real.py` | 10 | Post-quantum crypto (ML-KEM-1024) |
| `test_pq_hybrid.py` | 13 | Post-quantum hybrid (X25519 + ML-KEM) |
| `test_pqxdh_upgrade.py` | 25 | PQXDH: ML-KEM-768/1024, transcript binding, backward compat |
| `test_asymmetric_rekey.py` | 40 | MSR v2 asymmetric rekey: PCS, forward secrecy, rollback resistance |
| `test_high_security.py` | 34 | High security mode, secure wipe, memory protection |
| `test_audit_fixes.py` | — | OPUS-AUDIT remediation verification |
| `test_signal_invariants.py` | — | Signal protocol invariant enforcement |

> **Archived from TIER 3:** `test_forward_secrecy.py`, `test_forward_secrecy_decoder.py`, `test_forward_secrecy_encoder.py`, `test_forward_secrecy_x25519.py`, `test_schrodinger.py`, `test_quantum_mixer.py`, `test_multi_secret.py`, `test_secure_bridge.py`, `test_secure_cleanup.py`, `test_entropy_boost.py`, `test_double_ratchet.py`, `test_pq_signatures.py`, `test_pq_crypto.py`, `test_schrodinger_encode.py`, `test_schrodinger_decode.py` — moved to `tests/_archive/`

### TIER 4: UI/Integration/Infrastructure Tests

| File | Tests | Purpose |
|------|-------|---------|
| `test_cat_errors.py` | 51 | Cat-themed error system, fur_ball_error, pounce_on_errors |
| `test_cat_utils.py` | 78 | PurrLogger, NineLivesRetry, CatBreed, ASCII art |
| `test_tamper_report.py` | 19 | TamperReport rendering, JSON export |
| `test_bridge_protocol.py` | 21 | Mobile bridge wire protocol |
| `test_fuzz_targets.py` | 122 | Comprehensive fuzz harness testing |
| `test_property_based.py` | 20 | Hypothesis property-based tests |
| `test_rust_crypto_backend.py` | 12 | Rust backend integration |
| `test_hardware_integration.py` | 70 | Hardware security module integration |
| `test_stego_advanced.py` | 16 | Advanced steganography modes |
| `test_stego_phase1.py` | 49 | Phase 1 stego: temporal channel, adversarial perturbation, procedural cat generator, integration |
| `test_deadmans_switch_cli.py` | 5 | Dead man's switch CLI |
| `test_logo_eyes.py` | 3 | Logo eyes encoder, LogoConfig |
| `test_mobile_bridge.py` | 22 | Mobile bridge CLI handler, protocol data classes, BLE/USB |
| `test_progress.py` | 6 | ProgressBar class (production-only subset) |
| `test_security_warnings.py` | 4 | Security warning display |
| `test_crypto_DEBUG.py` | 2 | **DEPRECATED** — import smoke for quarantined `legacy_py/crypto_DEBUG.py` (safe to delete) |
| `test_encode_DEBUG.py` | 2 | **DEPRECATED** — import smoke for deprecated `encode_DEBUG` (safe to delete) |
| `test_setup.py` | 1 | Package setup.py/pyproject.toml validation |
| `test_cat_js_runner.py` | — | JavaScript cat mode test runner |
| `web_demo/test_all_modes.py` | 20 | Web demo integration: normal, cat APNG, cat server API, duress FS × 5 runs |
| `web_demo/test_cat_mode.py` | 1 | Cat mode APNG encode→decode roundtrip |

> **Archived from TIER 4:** `test_catnip_fountain.py`, `test_hardware_keys.py`, `test_meow_encode.py`, `test_decoy_generator.py`, `test_merkle_tree.py`, `test_ninja_cat_ultra.py`, `test_prowling_mode.py`, `test_resume_secured.py`, `test_profiling_improved.py`, `test_progress_modules.py`, `test_ascii_qr.py`, `test_bidirectional.py`, `test_clowder.py`, `test_dashboard_gui.py`, `test_debug_modules.py`, `test_logo_and_gui.py`, `test_webcam_modules.py`, `test_clowder_decode.py`, `test_clowder_encode.py`, `test_clowder_modules.py`, `test_decode_webcam_with_resume.py`, `test_gui.py`, `test_gui_logo_example.py`, `test_gui_modules.py`, `test_hardware.py`, `test_hardware_modules.py`, `test_meow_dashboard_demo.py`, `test_meow_gui_enhanced.py`, `test_progress_bar.py`, `test_webcam_enhanced.py` — moved to `tests/_archive/`

### TIER 5: CI/Enforcement Gate Tests

| File | Tests | Purpose |
|------|-------|---------|
| `test_production_boundary.py` | — | Production module boundary enforcement |
| `test_production_import_boundary.py` | 5 | Surface area regression: allowlist, staleness, archive guard |
| `test_no_experimental_imports_in_production.py` | — | No experimental imports in production code |
| `test_fail_closed_enforcement.py` | — | Fail-closed crypto enforcement |
| `test_no_overclaims.py` | — | No security overclaims in docs |
| `test_no_python_key_bytes.py` | — | No raw Python key bytes in production |
| `test_zero_key_bytes.py` | — | Key zeroization enforcement |
| `test_profile_required_and_checked.py` | — | Profile checks enforcement |

### Archived Tests (`tests/_archive/`)

52 test files covering non-production modules were moved to `tests/_archive/` during the February 2026 surface area minimization. These files are:

- **Not collected by pytest** (via `norecursedirs` in `pyproject.toml` and `conftest.py` in the archive dir)
- **Not included in coverage** (via `.coveragerc` omit rules)
- **Preserved intact** for restoration if their corresponding source modules return to production

See `docs/SURFACE_AREA_MINIMIZATION.md` for the complete list and restoration instructions.

### Rust Crypto Backend Tests

The project includes two Rust crypto packages with **261 total tests**:

#### rust_crypto (meow_crypto_rs) - PyO3 Bindings - 206 tests

| File | Tests | Purpose |
|------|-------|-------|
| `rust_crypto/src/pure.rs` (unit tests) | 41 | Pure Rust crypto operations: Argon2id, AES-GCM, HKDF, HMAC, SHA256, X25519, ML-KEM-1024 |
| `rust_crypto/tests/comprehensive_tests.rs` | 80 | Core crypto operations via PyO3 bindings |
| `rust_crypto/tests/additional_security_tests.rs` | 29 | Security edge cases: zeroization, failure modes, boundary conditions |
| `rust_crypto/tests/proptest_crypto.rs` | 23 | Property-based fuzzing with random inputs (original suite) |
| `rust_crypto/tests/property_tests.rs` | 14 | Adversarial property tests: nonce uniqueness, ratchet monotonicity, replay rejection, PCS healing, hybrid combiner, AAD canonicalization, manifest binding, fail-closed AEAD, commitment tags, Argon2id domain separation, X25519 symmetry, HKDF domain separation |
| `rust_crypto/tests/ffi_fuzz.rs` | 19 | FFI boundary fuzz: random/small/large/truncated/reordered inputs, corrupted PQ ciphertext, wrong salt/version, concurrent calls, encode→decode round-trip |

**Architecture Note:** The `rust_crypto/src/pure.rs` module contains all crypto logic without PyO3 dependencies. The PyO3 bindings in `lib.rs` are thin wrappers that call the pure functions. This separation enables comprehensive unit testing of the crypto logic.

**cargo-fuzz targets** (libFuzzer, run separately with `cargo +nightly fuzz run <target>`):

| Fuzz Target | Attack Classes Covered |
|-------------|------------------------|
| `fuzz_decrypt_frame` | Nonce reuse, Truncation oracle, Partial decrypt leak |
| `fuzz_header_parse` | Header tampering, AAD omission, Nonce reuse |
| `fuzz_hybrid_decapsulate` | Hybrid downgrade, PQ failure fallback, State compromise |
| `fuzz_ratchet_step` | Replay, Nonce reuse, PCS violation |
| `fuzz_full_decode_pipeline` | Partial decrypt leak, Truncation oracle, Replay |

#### crypto_core - Formally Verified Primitives - 110 tests

| File | Tests | Purpose |
|------|-------|---------|
| `crypto_core/src/*.rs` (unit tests) | 97 | Inline unit tests for AEAD, nonce, types, verus proofs; includes 8 GB-series runtime checks in `verus_guarded_buffer.rs` |
| `crypto_core/tests/core_smoke.rs` | 5 | Smoke tests for core functionality |
| `crypto_core/tests/coverage_tests.rs` | 47 | Comprehensive coverage tests for edge cases |
| `crypto_core/tests/security_properties.rs` | 17 | Security property verification tests || `crypto_core/tests/golden_vectors.rs` | 22 | Frozen golden vectors: HKDF, HMAC, AES-GCM, SHA-256, Argon2id, AES-CTR, X25519, ratchet chain, frame MAC |
| `crypto_core/tests/hsm_integration.rs` | — | HSM/PKCS#11 mock + real integration (feature-gated) |
| `crypto_core/tests/tpm_integration.rs` | — | TPM2 mock + real integration (feature-gated) |
| `crypto_core/tests/yubikey_integration.rs` | — | YubiKey PIV mock + real integration (feature-gated) |#### Requirements for Running Rust Tests

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify installation
rustc --version  # Should show 1.75.0 or later
cargo --version

# Optional: Install coverage tool
cargo install cargo-tarpaulin
```
#### Coverage Report (February 2026)

| Package | Module | Covered/Total | Coverage |
|---------|--------|---------------|----------|
| crypto_core | `src/aead_wrapper.rs` | 65/69 | **94.2%** |
| crypto_core | `src/nonce.rs` | 55/56 | **98.2%** |
| crypto_core | `src/pure_crypto.rs` | 121/121 | **100%** ✓ |
| crypto_core | `src/types.rs` | 28/29 | **96.6%** |
| crypto_core | `src/verus_kdf_proofs.rs` | 52/53 | **98.1%** |
| crypto_core | `src/verus_proofs.rs` | 10/10 | **100%** ✓ |
| crypto_core | `src/verus_guarded_buffer.rs` | 8/8 | **100%** ✓ (8 GB-series runtime tests) |
| **crypto_core** | **Total (excl. hardware stubs)** | **331/338** | **97.9%** ✓ |

**rust_crypto Coverage Note:** The `meow_crypto_rs` package uses PyO3 for Python bindings. Standard Rust coverage tools (cargo-tarpaulin, llvm-cov) cannot link the test binaries without Python symbols, preventing automated coverage measurement. However:
- The `pure.rs` module (41 tests) covers all crypto operations
- Integration tests (105 tests) verify PyO3 wrapper correctness
- The crypto logic is identical to the covered `crypto_core` primitives

**Uncovered lines** (non-testable):
- Nonce exhaustion paths (require 2^64 iterations)
- `#[cfg(debug_assertions)]` code paths
- Hardware module stubs (hsm.rs, yubikey_piv.rs) - require PKCS#11 hardware

**Run Rust tests:**
```bash
# rust_crypto (PyO3 bindings) - 206 tests
cargo test -p meow_crypto_rs              # All tests
cargo test -p meow_crypto_rs pure::       # Pure module tests (41)
cargo test --test comprehensive_tests     # Core functionality (80)
cargo test --test additional_security_tests  # Security edge cases (29)
cargo test --test proptest_crypto         # Property-based fuzzing (23)
cargo test --test property_tests          # Adversarial property tests (14)
cargo test --test ffi_fuzz                # FFI boundary fuzz (19)

# cargo-fuzz targets (requires nightly + cargo-fuzz)
cargo install cargo-fuzz --locked
cargo +nightly fuzz run fuzz_decrypt_frame       -- -max_total_time=60
cargo +nightly fuzz run fuzz_header_parse        -- -max_total_time=60
cargo +nightly fuzz run fuzz_hybrid_decapsulate  -- -max_total_time=60
cargo +nightly fuzz run fuzz_ratchet_step        -- -max_total_time=60
cargo +nightly fuzz run fuzz_full_decode_pipeline -- -max_total_time=60

# crypto_core (formally verified) - 110 tests
cargo test -p crypto_core                 # All tests
cargo test -p crypto_core --test coverage_tests     # Coverage tests
cargo test -p crypto_core --test security_properties  # Security properties

# Coverage report (requires cargo-tarpaulin)
cargo tarpaulin -p crypto_core --skip-clean  # 97.9% coverage
```

### February 2026 Coverage Expansion (Completed & Merged)

25 `*_comprehensive.py` test suites were created to close remaining gaps. These have since been merged into their corresponding 1-to-1 `test_<module>.py` files (Phase 1 consolidation). Tests now live directly in: `test_decoy_generator.py`, `test_high_security.py`, `test_security_warnings.py`, `test_cat_utils.py`, `test_progress_modules.py`, `test_ascii_qr.py`, `test_bidirectional.py`, `test_clowder.py`, `test_schrodinger.py`, `test_catnip_fountain.py`, `test_debug_modules.py`, `test_logo_and_gui.py`, `test_dashboard_gui.py`, `test_deadmans_switch_cli.py`, `test_webcam_modules.py`, and others.

**Naming convention:** Every `meow_decoder/<module>.py` has a corresponding `tests/test_<module>.py`. No `*_comprehensive.py` files remain.

### February 2026 Coverage Boost (95% Target)

Targeted coverage boost tests — originally in standalone files, now consolidated into module-specific test files
(Phase 0 consolidation, February 2026):

These standalone coverage-boost files were merged into their module-specific test files during Phase 0 consolidation:
- `test_coverage_boost_cat_utils.py` (66 tests) → `test_cat_utils.py`
- `test_coverage_boost_spec_v12.py` (28 tests) → `test_spec_v12.py`
- `test_coverage_boost_catnip.py` (10 tests) → `test_catnip_fountain.py`
- `test_coverage_boost_schrodinger.py` (18 tests) → `test_schrodinger.py`
- `test_coverage_boost_remaining.py` (67 tests) → decomposed into 20 module-specific files
- `test_coverage_boost_extras.py` (69 tests) → decomposed into 14 module-specific files

### February 2026 Cat-Themed Error System

| File | Tests | Purpose |
|------|-------|---------|
| `tests/test_cat_errors.py` | 40+ | Cat-themed exceptions, fur_ball_error catalog, pounce_on_errors decorator, litter_box_cleanup, output helpers, cat_translate_error, meow_excepthook |

### February 2026 Roadmap Completion (ST + MT Tasks)

Test suites for completed roadmap tasks — originally standalone, now merged into module-specific files
(Phase 0 consolidation, February 2026):

These standalone roadmap-task files were merged into module-specific test files during Phase 0 consolidation:
- `test_manifest_bounds.py` (17 tests, **ST-2**) → `test_crypto.py`
- `test_canonical_aad.py` (10 tests, **MT-1**) → `test_crypto.py`
- `test_timing_harness.py` (**MT-5**) → `test_crypto.py`
- `test_tamper_report.py` (19 tests, **MT-7**) — standalone (still exists)
- `test_bridge_protocol.py` (21 tests, **MT-8**) — standalone (still exists)

### February 2026 Security Audit (audit1.md)

Security regression tests — originally standalone, now merged into module-specific files
(Phase 0 consolidation, February 2026):

These standalone security-audit files were merged into module-specific test files during Phase 0 consolidation:
- `test_streaming_crypto_security.py` (14 tests, **CRIT-01**) → `test_streaming_crypto.py`
- `test_duress_timing_security.py` (12 tests, **HIGH-02**) → `test_duress_mode.py`

#### CRIT-01: AES-CTR Without Authentication (FIXED)

The `streaming_crypto.py` module was using AES-256-CTR without authentication, which allowed bit-flipping attacks. Fix includes:
- HMAC-SHA256 MAC computed over `nonce || ciphertext`
- MAC verification happens BEFORE any decryption
- HKDF domain separation for MAC key derivation

Tests added:
- `test_encrypt_returns_mac_tag` - Verify MAC output structure
- `test_roundtrip_with_mac_verification` - Full authenticated roundtrip
- `test_tampered_ciphertext_rejected` - Bit-flip attack detection
- `test_truncated_ciphertext_rejected` - Truncation attack detection
- `test_wrong_mac_rejected` - Invalid MAC rejection
- `test_mac_length_validation` - MAC format validation
- `test_mac_includes_nonce` - Nonce substitution prevention
- Plus 7 more tests for edge cases and key derivation

#### HIGH-02: Duress Timing Leak (FIXED)

The `duress_mode.py` module had timing side-channels that could reveal whether a duress password was entered. Fix includes:
- Dummy data wiping for timing equalization
- Both branches execute equivalent work
- Random timing delay after all operations

Tests added:
- `test_duress_vs_real_timing_similar` - Timing equivalence
- `test_wrong_password_timing_similar` - Wrong password timing
- `test_sensitive_data_zeroed_on_duress` - Data wiped on duress
- `test_sensitive_data_intact_on_real` - Data preserved on real
- Plus 8 more tests for password validation and dummy wipe

## Security Principles Applied

### 1. Fail-Closed Design
- All tests verify that failures are caught and handled safely
- No partial output on cryptographic errors
- Wrong passwords must produce clear rejection

### 2. Hostile Input Assumption
- Tests include tampered ciphertext
- Tests include corrupted manifests
- Tests include invalid parameters

### 3. Error Message Safety
- Error messages must not leak sensitive information
- Password values must never appear in errors
- Key material must never appear in errors

### 4. Constant-Time Operations
- Rust backend required for timing attack resistance
- Tests verify Rust backend availability

## Coverage Configuration

The `pyproject.toml` has been configured with:

```toml
[tool.coverage.run]
source = ["meow_decoder"]
branch = true
# Detailed omit list for TIER 3 modules

[tool.coverage.report]
fail_under = 35  # Incrementally increase to 80%+
```

### Coverage Targets

| Tier | Modules | Target | Status |
|------|---------|--------|--------|
| TIER 1 | crypto.py, crypto_backend.py, fountain.py, frame_mac.py, constant_time.py | 95-100% | Critical |
| TIER 2 | encode.py, decode_gif.py, config.py, qr_code.py, gif_handler.py | 90%+ | High |
| TIER 3 | Everything else | Best-effort | Low |
| **Rust** | crypto_core (aead, nonce, types, verus proofs) | 95%+ | **97.9% ✓** |
| **Rust** | rust_crypto (PyO3 bindings) | 90%+ | Tests only (PyO3 blocks tarpaulin) |

**Status:** Test suite consolidated (Phase 0 + Phase 1 complete) and minimized (surface area reduction). 59 active test files, 1541+ active Python tests. 52 test files archived to `tests/_archive/`. All `*_comprehensive.py` files merged into 1-to-1 counterparts. Phase 1 stego tests (49) and web demo integration tests (21) added.

## Running Tests

```bash
# ============ Python Tests ============
# Run all tests with coverage
pytest tests/ -v --cov=meow_decoder --cov-report=term-missing

# Run only security-critical tests (TIER 1)
pytest tests/test_crypto.py tests/test_crypto_backend.py tests/test_constant_time.py tests/test_frame_mac.py tests/test_streaming_crypto.py -v

# Run with HTML coverage report
pytest tests/ --cov=meow_decoder --cov-report=html

# Run property-based tests
pytest tests/test_property_based.py -v

# Run comprehensive fuzz harness tests (122 tests)
pytest tests/test_fuzz_targets.py -v

# Run all fuzz/property tests
pytest tests/test_fuzz_targets.py tests/test_property_based.py -v

# ============ Rust Crypto Tests ============
# Run all 206 Rust crypto tests
cargo test -p meow_crypto_rs

# Run individual Rust test suites
cargo test --test comprehensive_tests         # 80 core tests
cargo test --test additional_security_tests   # 29 security tests
cargo test --test proptest_crypto             # 23 property tests
```

## Test Categories

### Mandatory Security Tests (from requirements)

1. ✅ **Encrypt → Decrypt roundtrip** (`test_crypto.py`)
2. ✅ **Wrong key rejection** (`test_crypto.py`)

---

## Testing Infrastructure Overview

# 🧪 Meow Decoder Testing Infrastructure - Complete Overview

**Last Updated:** 2026-02-18
**Phase:** Phase 5 Week 1 Complete + Post-Rust Migration Audit + Surface Area Minimization
**Total Active Tests:** 1,541+ tests (Python) + 465 tests (Rust) = **2,006+ total active tests**
**Active Test Files:** 59 Python test files + 9 Rust test files
**Archived Test Files:** 52 Python test files in `tests/_archive/` (covering non-production modules)
**Migration Status:** All production crypto routes through Rust backend (`meow_crypto_rs`)

---

## 📊 Testing Pyramid

```
									┌──────────────┐
									│ E2E/CI Tests │  ← Phase 5 Week 1
									│  (21 videos) │
									└──────────────┘
								 ┌────────────────┐
								 │ Integration    │
								 │ Tests (80)     │
								 └────────────────┘
							 ┌──────────────────────┐
							 │ Security Tests (300+)│
							 └──────────────────────┘
						┌─────────────────────────────┐
						│ Unit Tests (1,100+)         │
						└─────────────────────────────┘
      ┌─────────────────────────────────────────────┐
      │ Archived Tests (52 files in tests/_archive/)│
      └─────────────────────────────────────────────┘
```

---

## 🎯 Phase 5 Week 1: Cat Mode Video Testing (NEW!)

**Status:** ✅ COMPLETE
**Created:** February 13, 2026
**Purpose:** Validate cat-mode video decoding with real-world error conditions

### Golden Test Videos (3 videos)

Located in: `tests/golden/*.webm`

| Video | Payload | Speed | Duration | Size | Purpose |
|-------|---------|-------|----------|------|---------|
| `cat_mode_golden_empty_hash_100ms.webm` | Empty SHA-256 hash | 100ms/bit | ~7s | 32 KB | Fast baseline test |
| `cat_mode_golden_short_150ms.webm` | Short message | 150ms/bit | ~5s | 31 KB | Slow bit rate test |
| `cat_mode_golden_long_50ms.webm` | Long message | 50ms/bit | ~12s | 49 KB | High-speed test |

**What They Test:**
- ✅ Preamble detection (alternating 1010... pattern)
- ✅ Sync word alignment (0xAA55 bit boundary lock)
- ✅ NRZ timing detection (fixed time windows)
- ✅ CRC32 packet validation
- ✅ Session locking (anti-injection)
- ✅ Green threshold calibration

**Cat Mode Stego Note:** Cat mode steganography uses **APNG** (not GIF) because GIF's 256-color palette quantization destroys LSB-embedded data. The decode pipeline includes automatic stego LSB extraction fallback (tries depths 2, 1, 3) and frame MAC index tracking for correct per-frame verification when stego extraction skips frames.

### Error Injection Test Videos (21 videos total)

Located in: `tests/golden/errors/*.webm`

**Error Modes (6 types × 3 base videos + 3 lighting variants):**

| Error Mode | Count | Description | Expected Behavior |
|------------|-------|-------------|-------------------|
| **frame_corruption** | 3 | 10% frames black (dropped frames) | ✅ Detect via CRC, report frame loss |
| **timing_jitter** | 3 | ±20% frame delays (buffering/lag) | ✅ Maintain sync, adaptive threshold |
| **partial_video** | 3 | Last 20% removed (recording stopped) | ✅ Detect incomplete, suggest retake |
| **wrong_roi** | 3 | 50px offset (user error) | ✅ Fail eye detection, suggest re-select |
| **extreme_lighting** | 6 | Dim (30%) or bright (170%) | ✅ Struggle but provide diagnostics |
| **resolution_degradation** | 3 | 50% downscale (low-quality camera) | ⚠️ Work with reduced confidence |

**What They Test:**
- ✅ Error detection and reporting
- ✅ Diagnostic message quality
- ✅ User-facing error messages
- ✅ Graceful degradation
- ✅ Frame loss tolerance (via fountain codes)

### Test Generation Scripts

**1. Golden Video Generator** (`tests/generate_golden_videos.js`)
```bash
npm run generate-golden-videos
# Creates 3 deterministic test videos in tests/golden/
# Uses node-canvas to render synthetic cat faces
# Controllable eye colors (green=1, dark=0)
# Outputs SHA-256 checksums for validation
```

**Files:**
- `tests/golden-video-lib.js` (400 lines) - CatFaceRenderer, encodePayload, generateFrames
- `tests/generate_golden_videos.js` (200 lines) - CLI wrapper, 3 test cases

**2. Error Injection Framework** (`tests/generate_error_tests.js`)
```bash
npm run generate-error-tests
# Creates 21 error-injected variants
# Uses ffmpeg for frame manipulation
# Generates manifest.json with metadata
# Outputs comprehensive README.md with checksums
```

**Files:**
- `tests/error_injection_lib.js` (600 lines) - 6 error modes, SeededRandom
- `tests/generate_error_tests.js` (350 lines) - Batch generator, documentation
- `tests/run_error_tests.py` (250 lines) - Python validation suite

**3. Validation Runner** (`tests/run_error_tests.py`)
```bash
python3 tests/run_error_tests.py
# Validates error handling for all 21 error videos
# Checks expected failure modes
# Reports diagnostic message quality
```

### CI/CD Integration

**GitHub Actions Gates (3 new gates added):**

| Gate | File | Purpose | Status |
|------|------|---------|--------|
| **Gate 2a** | `.github/workflows/ci.yml` | Golden video checksum verification | ✅ Added |
| **Gate 3a** | `.github/workflows/ci.yml` | Error injection validation | ✅ Added |
| **Gate 3b** | `.github/workflows/ci.yml` | Cross-browser testing (Playwright) | ✅ Added |

**Workflow Steps:**
1. Install dependencies (canvas, ffmpeg, playwright)
2. Generate golden videos
3. Validate checksums match expected
4. Generate error test videos
5. Run error validation suite
6. Run cross-browser tests (8 configs × 14 tests = 112 tests)

---

## 🔐 Security Test Suite (Python)

**Active:** 1,492+ tests across 57 files
**Archived:** 52 test files in `tests/_archive/` (covering non-production modules)
**Coverage:** 92% overall, 97%+ for crypto-critical modules

### Post-Rust Migration Audit (February 2026)

All Python crypto operations now route through `meow_decoder.crypto_backend` → `meow_crypto_rs` (Rust).
The `test_crypto_enforcement.py` AST scanner verifies no production code imports Python `cryptography`.
The `conftest.py` calls `pytest.exit()` if `meow_crypto_rs` is unavailable (fail-closed).

**Remaining `from cryptography` in tests (12 occurrences, 5 files):** These are test fixture imports only — generating X25519/Ed25519 PEM files for CLI/rejection tests. They do NOT test Python crypto internals. See "Migration Exceptions" below.

**Files slated for deletion:** `test_crypto_DEBUG.py`, `test_encode_DEBUG.py` (import-only smoke tests for deprecated `legacy_py/` modules, zero security coverage).
**Historical artifact:** `characterize_ctr.py` (one-time AES-CTR characterization script, superseded by Rust golden vector in `crypto_core/tests/golden_vectors.rs`).

### Tier 1: Crypto-Critical (95-100% coverage)

| Module | Tests | Coverage | Purpose |
|--------|-------|----------|---------|
| `test_crypto.py` | 205 | 97% | AES-256-GCM, KDF, AAD, manifest |
| `test_crypto_backend.py` | 105 | 96% | Rust bridge bindings |
| `test_constant_time.py` | 45 | 98% | Timing attack resistance |
| `test_frame_mac.py` | 11 | 100% | Frame authentication |
| `test_fountain.py` | 12 | 94% | Fountain codes |

**What They Test:**
- ✅ Encryption/decryption correctness
- ✅ Key derivation (Argon2id)
- ✅ AAD construction (manifest binding)
- ✅ Nonce uniqueness
- ✅ Auth tag verification
- ✅ Constant-time operations

### Tier 2: Security Features

| Module | Tests | Purpose |
|--------|-------|---------|
| `test_security.py` | 20 | Tamper detection |
| `test_adversarial.py` | 20 | Hostile input handling |
| `test_sidechannel.py` | 11 | Side-channel resistance |
| `test_forward_secrecy.py` | 34 | X25519 ephemeral keys |
| `test_duress_mode.py` | 57 | Decoy data, plausible deniability |
| `test_schrodinger.py` | 40 | Dual-secret quantum superposition |
| `test_pq_crypto_real.py` | 10 | ML-KEM-1024 post-quantum |

**What They Test:**
- ✅ Manifest tampering detection
- ✅ Frame injection rejection
- ✅ Timing oracle prevention
- ✅ Forward secrecy (MEOW3)
- ✅ Duress mode decoy generation
- ✅ Schrödinger dual-secret encoding
- ✅ Post-quantum hybrid encryption

### Tier 3: Core Pipeline

| Module | Tests | Purpose |
|--------|-------|---------|
| `test_encode.py` | 63 | Encoding pipeline |
| `test_decode_gif.py` | 49 | GIF decoding |
| `test_qr_code.py` | 16 | QR generation/reading |
| `test_gif_handler.py` | 13 | GIF frame handling |

**What They Test:**
- ✅ File → compress → encrypt → QR → GIF
- ✅ GIF → QR → decrypt → decompress → file
- ✅ Fountain code reconstruction
- ✅ Metadata obfuscation

### Tier 4: Integration & E2E

| Module | Tests | Purpose |
|--------|-------|---------|
| `test_encode.py` | 63 | Encoding pipeline, QR generation, roundtrips |
| `test_decode_gif.py` | 49 | GIF decoding, frame extraction |
| `test_property_based.py` | 20 | Hypothesis fuzzing |
| `test_fuzz_targets.py` | 122 | Comprehensive fuzzing |

**What They Test:**
- ✅ Full encode → decode roundtrips
- ✅ Random input fuzzing (100 iterations)
- ✅ Edge cases (empty files, large files, binary)
- ✅ Error recovery

---

## 🦀 Rust Test Suite

**Total:** 465 tests across 2 packages

### Package 1: rust_crypto (PyO3 Bindings) - 206 tests

| Module | Tests | Purpose |
|--------|-------|---------|-----|
| `src/pure.rs` (unit) | 41 | Pure Rust crypto (no PyO3) |
| `tests/comprehensive_tests.rs` | 80 | PyO3 bindings |
| `tests/additional_security_tests.rs` | 29 | Security edge cases |
| `tests/proptest_crypto.rs` | 23 | Property-based fuzzing (original suite) |
| `tests/property_tests.rs` | 14 | Adversarial property tests: nonce uniqueness, ratchet monotonicity, replay, PCS healing, hybrid combiner, AAD canonicalization, manifest binding, fail-closed AEAD |
| `tests/ffi_fuzz.rs` | 19 | FFI boundary fuzz: attacker-controlled inputs across the PyO3 boundary, encode→decode round-trip, concurrent calls |

**What They Test:**
- ✅ Argon2id KDF
- ✅ AES-256-GCM encryption
- ✅ HKDF key derivation
- ✅ HMAC-SHA256 authentication
- ✅ X25519 key exchange
- ✅ ML-KEM-1024 post-quantum
- ✅ Zeroization on drop
- ✅ Constant-time operations
- ✅ Nonce uniqueness (proptest)
- ✅ Ratchet monotonicity + PCS healing (proptest)
- ✅ Replay rejection (proptest)
- ✅ Hybrid combiner integrity (proptest)
- ✅ FFI boundary: panic-free on all attacker-controlled inputs

### Package 2: crypto_core (Formally Verified) - 110 tests

| Module | Tests | Coverage | Purpose |
|--------|-------|----------|---------|
| `src/pure_crypto.rs` | 89 | 100% | Pure crypto primitives |
| `tests/coverage_tests.rs` | 47 | — | Edge case coverage |
| `tests/security_properties.rs` | 17 | — | Security invariants |
| `tests/core_smoke.rs` | 5 | — | Smoke tests |

**What They Test:**
- ✅ Verus formal verification proofs
- ✅ GuardedBuffer (`SecureBox`) bounds safety — 8 GB-series proofs in `verus_guarded_buffer.rs` (GB-001 through GB-008: layout, overflow, underflow, size, alignment, zeroize-on-drop)
- ✅ Nonce management invariants
- ✅ AEAD wrapper correctness
- ✅ Type safety guarantees

**Coverage:** 97.9% (331/338 lines, excluding hardware stubs)

---

## 🌐 Cross-Browser Testing (Playwright)

**Status:** ✅ Code complete (Alpine limitation: browsers not installed)
**Location:** `tests/test_cross_browser.spec.js`

### Browser Configurations (8 total)

| Config | Browser | Viewport | DPI | Platform |
|--------|---------|----------|-----|----------|
| Desktop Chrome | Chromium (latest) | 1920×1080 | 1.0 | Linux |
| Desktop Firefox | Firefox (latest) | 1920×1080 | 1.0 | Linux |
| Desktop Safari | WebKit (latest) | 1920×1080 | 1.0 | Linux |
| Mobile Chrome | Chromium | 412×915 | 2.0 | Android |
| Mobile Safari | WebKit | 390×844 | 3.0 | iOS |
| Tablet Chrome | Chromium | 820×1180 | 2.0 | Android |
| Low-end Mobile | Chromium | 360×640 | 1.5 | Android |
| High DPI Desktop | Chromium | 2560×1440 | 2.0 | Linux |

### Test Cases (14 tests × 8 configs = 112 total)

| Test | Purpose |
|------|---------|
| Page loads | Verify wasm_browser_example.html loads |
| WebAssembly loads | Rust crypto backend initializes |
| Encode text | Basic text encoding |
| Decode QR | QR code decoding |
| Cat mode encode | Cat face rendering |
| WebRTC camera | Camera permissions/access |
| Video decode | Video frame extraction |
| Error handling | Invalid input handling |
| Mobile gestures | Touch/swipe interactions |
| Performance | Decode time < 5s threshold |
| Memory usage | No memory leaks |
| Offline mode | Service worker functionality |
| Share API | Native sharing |
| File handling | Drag-and-drop |

**Expected Pass Rate:** ≥90% (106/112)

---

## 📋 Test Execution Guide

### Quick Start (All Tests)

```bash
# Python unit/integration tests
make test
# or
pytest tests/ -v --cov=meow_decoder

# Rust tests
cargo test --all

# Cat mode golden tests
npm run generate-golden-videos
npm run generate-error-tests
python3 tests/run_error_tests.py

# Cross-browser tests (Ubuntu/Debian only)
npm run test:browsers
```

### Individual Test Suites

```bash
# Crypto tests only
pytest tests/test_crypto*.py -v

# Security tests only
pytest tests/test_security*.py tests/test_adversarial.py -v

# Cat mode protocol tests
open tests/test_cat_protocol.html  # In browser
open tests/test_cat_mode_golden.html  # With test videos

# Fountain codes
pytest tests/test_fountain.py -v
open examples/test_fountain.html  # JavaScript version

# Side-channel tests
pytest tests/test_sidechannel.py -v

# Formal verification
cd formal/tla && tlc meow_protocol.tla
cd formal/proverif && proverif meow_protocol.pv
```

### CI/CD Locally

```bash
# Run full CI pipeline locally
act -j test  # Requires https://github.com/nektos/act

# Or manually:
make install-dev
make lint
make test
make sidechannel-test
make integration-test
```

---

## 📈 Coverage Reports

### Python Coverage (pytest-cov)

```bash
# Generate HTML coverage report
pytest tests/ --cov=meow_decoder --cov-report=html
open htmlcov/index.html
```

**Current Coverage (February 2026):**
- Overall (production modules only): **92%**
- Crypto modules: **97%+**
- Core pipeline: **89%**
- UI/CLI: **75%** (expected lower)
- Non-production modules: archived to `meow_decoder/_archive/`, excluded from coverage

### Rust Coverage (tarpaulin)

```bash
# Generate coverage report
cd rust_crypto && cargo tarpaulin --out Html
open tarpaulin-report.html

# Or for crypto_core
cd crypto_core && cargo tarpaulin --out Html
```
3. ✅ **Ciphertext tampering detection** (`test_crypto.py`)
4. ✅ **Auth tag tampering detection** (`test_crypto.py`)
5. ✅ **Nonce uniqueness** (`test_crypto.py`)
6. ✅ **KDF determinism** (`test_crypto.py`)
7. ✅ **Salt variation produces different keys** (`test_crypto.py`)
8. ✅ **Password variation produces different keys** (`test_crypto.py`)
9. ✅ **Lossless encode/decode** (`test_encode.py`)
10. ✅ **Various file sizes** (`test_encode.py`)
11. ✅ **Binary data (null bytes, high bytes)** (`test_encode.py`)

### CLI Tests

1. ✅ **Help text** (`test_meow_encode.py`)
2. ✅ **Missing required arguments** (`test_encode.py`)
3. ✅ **Nonexistent input file** (`test_encode.py`)
4. ✅ **Empty password rejection** (`test_crypto.py`)
5. ✅ **Exit codes** (`test_meow_encode.py`)

### Fuzz/Property Tests

1. ✅ **Random input testing** (`test_property_based.py`)
2. ✅ **Corruption detection** (`test_property_based.py`)
3. ✅ **Boundary conditions** (`test_property_based.py`)
4. ✅ **Manifest parsing harness** (`test_fuzz_targets.py`) - 18 tests
5. ✅ **Crypto boundary harness** (`test_fuzz_targets.py`) - 16 tests
6. ✅ **Fountain code harness** (`test_fuzz_targets.py`) - 19 tests
7. ✅ **AFL++ integration** (`test_fuzz_targets.py`) - 3 tests
8. ✅ **Corpus generation** (`test_fuzz_targets.py`) - 12 tests
9. ✅ **Integration & error handling** (`test_fuzz_targets.py`) - 17 tests
10. ✅ **Adversarial property tests — Rust** (`property_tests.rs`) - 14 tests: nonce uniqueness, ratchet monotonicity, replay rejection, PCS healing, hybrid combiner, AAD canonicalization, manifest binding, fail-closed AEAD, commitment tags, domain separation
11. ✅ **FFI boundary fuzz — Rust** (`ffi_fuzz.rs`) - 19 tests: random/small/large/truncated/reordered bytes, corrupted PQ ciphertext, wrong salt/version, concurrent calls, round-trip correctness
12. ✅ **cargo-fuzz targets** (libFuzzer): `fuzz_decrypt_frame`, `fuzz_header_parse`, `fuzz_hybrid_decapsulate`, `fuzz_ratchet_step`, `fuzz_full_decode_pipeline` — run in CI via `rust-security-suite.yml`

## Shared Fixtures (conftest.py)

The `conftest.py` provides:
- `random_salt` - 16-byte salt
- `random_nonce` - 12-byte nonce
- `valid_password` - Valid password for tests
- `short_password` - Invalid password for negative tests
- `random_key` - 32-byte encryption key
- `sample_plaintext` - Test data
- `sample_file` - Test file on disk
- `temp_directory` - Temporary directory
- `keyfile` - Valid keyfile
- `invalid_keyfile` - Invalid keyfile for negative tests

## Next Steps

1. **Run pytest** to validate all tests pass
2. **Review coverage report** to identify gaps
3. **Incrementally increase** `fail_under` threshold
4. **Add more tests** for edge cases as discovered

## Philosophy

> "Treat this code as if it protects real users under real threat models."

Every test in this suite assumes:
- Attackers are actively trying to break the crypto
- Error messages may be observed
- Timing information may be measured
- Partial failures must not leak data
