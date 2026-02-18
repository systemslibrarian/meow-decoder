# 🔐 Security-Focused Test Suite - Implementation Summary

## Overview

This document summarizes the security-focused test suite created for Meow Decoder v1.0 and expanded in February 2026.

**Current stats (February 2026):** 96 test files, 2413 Python tests + 261 Rust tests = **2674 total**.
**Migration status:** All production crypto routes through Rust backend (`meow_crypto_rs`).
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
| `test_crypto_enhanced.py` | 87 | Enhanced crypto with secure memory, SecureBytes |
| `test_constant_time.py` | 45 | Constant-time comparison, secure memset, timing consistency |
| `test_frame_mac.py` | 11 | Frame MAC authentication, key derivation, pack/unpack |
| `test_streaming_crypto.py` | 113 | Streaming encryption, MAC authentication, memory monitoring |
| `test_fountain.py` | 12 | Fountain code encoding/decoding, droplet generation |
| `test_golden_vectors.py` | 30 | Frozen golden vectors: Argon2id, HKDF, AES-GCM, HMAC, SHA-256, AAD, ratchet, pipeline |
| `test_crypto_enforcement.py` | 5 | AST-enforced Python crypto ban — fail-closed CI gate |
| `test_ratchet.py` | 142 | MSR v1 symmetric ratchet: domain separation, forward secrecy, replay, commitment tags |

### TIER 2: Core Pipeline Tests (90%+ coverage target)

| File | Tests | Purpose |
|------|-------|---------|
| `test_encode.py` | 63 | Encoding pipeline, QR generation, frame assembly |
| `test_decode_gif.py` | 49 | GIF decoding, frame extraction, QR reading |
| `test_gif_handler.py` | 13 | GIF creation, frame handling, size validation |
| `test_qr_code.py` | 16 | QR code generation and reading |
| `test_config.py` | 17 | EncodingConfig, MeowConfig, DuressConfig |
| `test_spec_v12.py` | 37 | Spec v1.2 encode/decode, key management, steganography |
| `test_metadata_obfuscation.py` | 17 | Length padding, corruption detection |
| `test_coverage_gaps_phase1.py` | 79 | Cross-module coverage gaps (streaming crypto, schrodinger, manifests) |
| `test_e2e_crypto_fountain.py` | 23 | E2E pipeline: encrypt→fountain→corrupt/reorder/drop→decode→decrypt |
| `test_e2e_ratchet_pipeline.py` | 23 | E2E pipeline with per-frame ratchet under loss/reorder |
| `test_fountain_montecarlo.py` | 10 | Monte Carlo statistical reliability of LT codes under frame loss |

### TIER 3: Security Features Tests

| File | Tests | Purpose |
|------|-------|---------|
| `test_security.py` | 20 | Tamper detection, auth tag verification |
| `test_adversarial.py` | 20 | Hostile input handling, corruption resilience |
| `test_sidechannel.py` | 11 | Side-channel resistance |
| `test_invariants.py` | 11 | Security invariant checks |
| `test_forward_secrecy.py` | 34 | X25519 forward secrecy (MEOW3) |
| `test_x25519_forward_secrecy.py` | 45 | X25519 key derivation, hybrid keys |
| `test_forward_secrecy_decoder.py` | 5 | Forward secrecy decoding |
| `test_forward_secrecy_encoder.py` | 3 | Forward secrecy encoding |
| `test_forward_secrecy_x25519.py` | 7 | Legacy X25519 compat |
| `test_duress_mode.py` | 57 | Duress mode, decoy data, timing equalization |
| `test_timelock_duress.py` | 32 | Timelock puzzles, countdown duress, deadman switch |
| `test_schrodinger.py` | 40 | Schrödinger dual-secret encode/decode (merged from comprehensive) |
| `test_quantum_mixer.py` | 97 | Quantum entanglement/collapse, statistical tests (merged from comprehensive) |
| `test_multi_secret.py` | 84 | Multi-secret encoding, Merkle trees, indistinguishability |
| `test_secure_bridge.py` | 60 | Rust secure bridge, key handles, HMAC |
| `test_secure_cleanup.py` | 13 | Sensitive buffer registration, cleanup |
| `test_high_security.py` | 34 | High security mode, secure wipe, memory protection |
| `test_entropy_boost.py` | 90 | Entropy pool, enhanced salt/nonce, hardware entropy |
| `test_double_ratchet.py` | 27 | Signal-style key ratcheting |
| `test_pq_crypto_real.py` | 10 | Post-quantum crypto (ML-KEM-1024) |
| `test_pq_hybrid.py` | 13 | Post-quantum hybrid (X25519 + ML-KEM) |
| `test_pq_signatures.py` | 10 | Post-quantum signatures |
| `test_pq_crypto.py` | 3 | Post-quantum module imports (pq_crypto_real, pq_hybrid, pq_signatures) |
| `test_pqxdh_upgrade.py` | 25 | PQXDH: ML-KEM-768/1024, transcript binding, backward compat |
| `test_asymmetric_rekey.py` | 40 | MSR v2 asymmetric rekey: PCS, forward secrecy, rollback resistance |
| `test_schrodinger_encode.py` | 1 | Schrödinger encoder module import |
| `test_schrodinger_decode.py` | 1 | Schrödinger decoder module import |

### TIER 4: UI/Integration/Infrastructure Tests

| File | Tests | Purpose |
|------|-------|---------|
| `test_cat_errors.py` | 51 | Cat-themed error system, fur_ball_error, pounce_on_errors |
| `test_cat_utils.py` | 78 | PurrLogger, NineLivesRetry, CatBreed, ASCII art |
| `test_catnip_fountain.py` | 14 | Catnip fountain encoder/decoder |
| `test_tamper_report.py` | 19 | TamperReport rendering, JSON export |
| `test_bridge_protocol.py` | 21 | Mobile bridge wire protocol |
| `test_fuzz_targets.py` | 122 | Comprehensive fuzz harness testing |
| `test_property_based.py` | 20 | Hypothesis property-based tests |
| `test_rust_crypto_backend.py` | 12 | Rust backend integration |
| `test_hardware_integration.py` | 70 | Hardware security module integration |
| `test_hardware_keys.py` | 44 | Hardware key management |
| `test_stego_advanced.py` | 16 | Advanced steganography modes |
| `test_meow_encode.py` | 5 | CLI encode integration |
| `test_decoy_generator.py` | 12 | Decoy data generation |
| `test_merkle_tree.py` | 78 | Merkle tree construction/verification |
| `test_ninja_cat_ultra.py` | 37 | Ninja cat encoding mode (merged from comprehensive) |
| `test_prowling_mode.py` | 21 | Prowling mode steganography |
| `test_resume_secured.py` | 62 | Secure resume/checkpoint |
| `test_profiling_improved.py` | 60 | Performance profiling |
| `test_progress_modules.py` | 16 | Progress tracking (merged from comprehensive) |
| `test_ascii_qr.py` | 12 | ASCII QR rendering (merged from comprehensive) |
| `test_bidirectional.py` | 6 | Bidirectional transfer |
| `test_clowder.py` | 7 | Clowder multi-device (merged from comprehensive) |
| `test_dashboard_gui.py` | 2 | Dashboard GUI |
| `test_deadmans_switch_cli.py` | 5 | Dead man's switch CLI |
| `test_debug_modules.py` | 9 | Debug module variants (merged from comprehensive) |
| `test_logo_and_gui.py` | 11 | Logo/GUI rendering (comprehensive was subset) |
| `test_security_warnings.py` | 4 | Security warning display |
| `test_webcam_modules.py` | 8 | Webcam capture modules (merged from comprehensive) |
| `test_clowder_decode.py` | 3 | Clowder decode module, password hashing |
| `test_clowder_encode.py` | 2 | Clowder encode module, ClowderManifest |
| `test_clowder_modules.py` | 9 | Clowder modules coverage (decode, encode, 95% target) |
| `test_crypto_DEBUG.py` | 2 | **DEPRECATED** — import smoke for quarantined `legacy_py/crypto_DEBUG.py` (safe to delete) |
| `test_encode_DEBUG.py` | 2 | **DEPRECATED** — import smoke for deprecated `encode_DEBUG` (safe to delete) |
| `test_decode_webcam_with_resume.py` | 1 | Webcam decode with resume module import |
| `test_gui.py` | 6 | GUI module imports (dashboard, enhanced, logo) |
| `test_gui_logo_example.py` | 2 | GUI logo example module |
| `test_gui_modules.py` | 6 | GUI modules coverage (logo window, dpg handling) |
| `test_hardware.py` | 8 | Hardware integration, HardwareSecurityProvider |
| `test_hardware_modules.py` | 10 | Hardware modules coverage (capabilities, providers) |
| `test_logo_eyes.py` | 3 | Logo eyes encoder, LogoConfig |
| `test_meow_dashboard_demo.py` | 2 | Dashboard demo module import |
| `test_meow_gui_enhanced.py` | 2 | Enhanced GUI module, MeowGuiEnhanced |
| `test_mobile_bridge.py` | 22 | Mobile bridge CLI handler, protocol data classes, BLE/USB |
| `test_progress.py` | 8 | Progress bar module, ProgressBar class |
| `test_progress_bar.py` | 3 | progress_bar module import, ProgressBar |
| `test_setup.py` | 1 | Package setup.py/pyproject.toml validation |
| `test_webcam_enhanced.py` | 1 | Enhanced webcam module import |

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
| `crypto_core/src/*.rs` (unit tests) | 89 | Inline unit tests for AEAD, nonce, types, verus proofs |
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

**Status:** Test suite consolidated (Phase 0 + Phase 1 complete). 87 test files, 2413 Python tests. All `*_comprehensive.py` files merged into 1-to-1 counterparts.

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
# Run all 128 Rust crypto tests
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
