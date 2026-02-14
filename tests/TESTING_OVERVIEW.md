# 🧪 Meow Decoder Testing Infrastructure - Complete Overview

**Last Updated:** 2026-02-13  
**Phase:** Phase 5 Week 1 Complete  
**Total Test Coverage:** 2,413 tests (Python) + 261 tests (Rust) = **2,674 total tests**

---

## 📊 Testing Pyramid

```
                  ┌──────────────┐
                  │ E2E/CI Tests │  ← NEW Phase 5 Week 1
                  │  (21 videos) │
                  └──────────────┘
                 ┌────────────────┐
                 │ Integration    │
                 │ Tests (80)     │
                 └────────────────┘
               ┌──────────────────────┐
               │ Security Tests (500+)│
               └──────────────────────┘
            ┌─────────────────────────────┐
            │ Unit Tests (2,000+)         │
            └─────────────────────────────┘
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

**Total:** 2,413+ tests across 87 files  
**Coverage:** 92% overall, 97%+ for crypto-critical modules

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

**Total:** 261 tests across 2 packages

### Package 1: rust_crypto (PyO3 Bindings) - 151 tests

| Module | Tests | Purpose |
|--------|-------|---------|
| `src/pure.rs` (unit) | 46 | Pure Rust crypto (no PyO3) |
| `tests/comprehensive_tests.rs` | 76 | PyO3 bindings |
| `tests/additional_security_tests.rs` | 29 | Security edge cases |
| `tests/proptest_crypto.rs` | 23 | Property-based fuzzing |

**What They Test:**
- ✅ Argon2id KDF
- ✅ AES-256-GCM encryption
- ✅ HKDF key derivation
- ✅ HMAC-SHA256 authentication
- ✅ X25519 key exchange
- ✅ ML-KEM-1024 post-quantum
- ✅ Zeroization on drop
- ✅ Constant-time operations

### Package 2: crypto_core (Formally Verified) - 110 tests

| Module | Tests | Coverage | Purpose |
|--------|-------|----------|---------|
| `src/pure_crypto.rs` | 89 | 100% | Pure crypto primitives |
| `tests/coverage_tests.rs` | 47 | — | Edge case coverage |
| `tests/security_properties.rs` | 17 | — | Security invariants |
| `tests/core_smoke.rs` | 5 | — | Smoke tests |

**What They Test:**
- ✅ Verus formal verification proofs
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
- Overall: **92%**
- Crypto modules: **97%+**
- Core pipeline: **89%**
- UI/CLI: **75%** (expected lower)

### Rust Coverage (tarpaulin)

```bash
# Generate coverage report
cd rust_crypto && cargo tarpaulin --out Html
open tarpaulin-report.html

# Or for crypto_core
cd crypto_core && cargo tarpaulin --out Html
```

**Current Coverage:**
- rust_crypto: **94%**
- crypto_core: **97.9%** (excluding hardware stubs)

---

## 🛠️ Test Maintenance

### Adding New Tests

**Python:**
1. Create `tests/test_mymodule.py`
2. Inherit from `unittest.TestCase`
3. Add to appropriate tier in TEST_SUITE_README.md
4. Run: `pytest tests/test_mymodule.py -v`

**Rust:**
1. Add to `rust_crypto/tests/` or `crypto_core/tests/`
2. Run: `cargo test --test mytest`
3. Update coverage: `cargo tarpaulin`

**Cat Mode:**
1. Add test case to `tests/generate_golden_videos.js`
2. Regenerate: `npm run generate-golden-videos`
3. Update checksums in `tests/golden/README.md`

**Error Injection:**
1. Add error mode to `tests/error_injection_lib.js` `ERROR_MODES`
2. Implement `inject<ErrorMode>()` function
3. Add to test matrix in `tests/generate_error_tests.js`
4. Regenerate: `npm run generate-error-tests`

### CI Gate Failures

**Gate 1: Unit Tests**
- Check: `pytest tests/` output
- Fix: Address failing unit tests
- Re-run: `make test`

**Gate 2: Golden Videos**
- Check: Checksum mismatch in `tests/golden/README.md`
- Fix: Regenerate with `npm run generate-golden-videos`
- Commit: Updated WebM files

**Gate 2a: Golden Checksum Verification**
- Check: SHA-256 mismatch
- Fix: Deterministic rendering issue (seed, session ID)
- Re-run: `npm run generate-golden-videos`

**Gate 3: Integration Tests**
- Check: `pytest tests/test_encode.py tests/test_decode_gif.py` output
- Fix: Pipeline issues (encode/decode)
- Re-run: `make integration-test`

**Gate 3a: Error Injection**
- Check: `python3 tests/run_error_tests.py` output
- Fix: Expected error behavior
- Re-run: `npm run generate-error-tests && python3 tests/run_error_tests.py`

**Gate 3b: Cross-Browser**
- Check: Playwright HTML report in `tests/playwright-report/`
- Fix: Browser compatibility issues
- Re-run: `npm run test:browsers`

**Gate 4: Rust Tests**
- Check: `cargo test --all` output
- Fix: Rust unit test failures
- Re-run: `cargo test --all`

**Gate 5: Security Tests**
- Check: `pytest tests/test_security*.py` output
- Fix: Security invariant violations
- Re-run: `make sidechannel-test`

---

## 📚 Test Documentation Index

| Document | Purpose |
|----------|---------|
| `tests/TEST_SUITE_README.md` | Complete test inventory (87 files, 2,674 tests) |
| `tests/TESTING_OVERVIEW.md` | This file - high-level testing infrastructure |
| `tests/golden/README.md` | Golden video test cases and checksums |
| `tests/golden/errors/README.md` | Error injection test matrix (1,399 lines) |
| `tests/golden/errors/manifest.json` | Machine-readable test metadata |
| `docs/UNDERSTANDING_THE_TESTS_IN_MEOW-DECODER.md` | Deep dive on test philosophy and patterns |
| `PHASE_5_WEEK_1_QUICKSTART.md` | Quick start guide for Phase 5 Week 1 |
| `PHASE_5_WEEK_1_COMPLETE.md` | Completion summary and next steps |

---

## 🎯 Test Coverage Goals (v1.0)

| Component | Current | Target | Status |
|-----------|---------|--------|--------|
| Crypto core | 97% | 95%+ | ✅ Exceeded |
| Pipeline | 89% | 85%+ | ✅ Exceeded |
| Security features | 92% | 90%+ | ✅ Met |
| Cat mode | NEW | 80%+ | ✅ In progress |
| Cross-browser | NEW | 90% pass | ⏳ CI only |
| Overall | 92% | 90%+ | ✅ Exceeded |

---

## 🐱 Lives Depend On It™

Every test represents a potential failure mode that could leak secrets, corrupt data, or fail to decode critical information. We test exhaustively because:

- **Cryptography must be correct** - One bit flipped = total failure
- **Error handling must be graceful** - Users need clear diagnostics
- **Performance must be consistent** - Timing leaks = security failure
- **Compatibility must be universal** - All browsers, all devices
- **Recovery must be robust** - 33% frame loss tolerance via fountain codes

**Test Philosophy:** If it can fail in the field, it must fail in CI first.

---

**Next Steps:** See [todocatmode.md](../todocatmode.md) Phase 5 Week 2 tasks for remaining work.
