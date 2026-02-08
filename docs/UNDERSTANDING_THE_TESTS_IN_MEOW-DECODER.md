# What Do the Tests in meow-decoder Actually Do?

**Version:** 1.2.0 (SECURITY-REVIEWED v1.0 INTERNAL REVIEW)  
**Last Updated:** 2026-02-08  
**Test Count:** 80 Python test modules (2359 tests) + 261 Rust tests

---

meow-decoder is **not** a typical app. It's a high-stakes security tool designed to protect sensitive files from powerful adversaries — including governments, law enforcement, or coercive actors who might force someone to reveal a password.

Because the stakes are so high (lives, freedom, safety of dissidents/journalists/activists), the tests in this project are **very different** from what you might see in a normal web app, game, or utility.

---

## 📂 Complete Test Inventory

The `tests/` folder contains **80 test modules** organized by security tier:

### TIER 1: Crypto-Critical Tests (95-100% coverage target) 🔐

These tests protect the core cryptographic operations. Failures here could leak secrets.

| Test File | What It Tests |
|-----------|---------------|
| `test_crypto.py` | AES-256-GCM encryption, decryption, tampering detection |
| `test_crypto_backend.py` | Rust/Python crypto backend selection, FFI bridge |
| `test_crypto_enhanced.py` | SecureBytes, memory wiping, constant-time HMAC |
| `test_constant_time.py` | Timing attack resistance, secure comparisons |
| `test_frame_mac.py` | Per-frame authentication, replay prevention |
| `test_fountain.py` | Fountain code encoding/decoding, loss tolerance |
| `test_forward_secrecy.py` | Per-block key derivation, ratcheting |
| `test_forward_secrecy_x25519.py` | X25519 ephemeral key agreement |
| `test_forward_secrecy_encoder.py` | Forward secrecy in encoding path |
| `test_forward_secrecy_decoder.py` | Forward secrecy in decoding path |
| `test_x25519_forward_secrecy.py` | Key generation, serialization, shared secrets |
| `test_pq_crypto_real.py` | Post-quantum ML-KEM-768/1024 integration |
| `test_pq_hybrid.py` | X25519 + ML-KEM hybrid mode |
| `test_pq_signatures.py` | Dilithium3 / Ed25519 manifest signatures |
| `test_metadata_obfuscation.py` | Length padding, size class hiding |
| `test_security.py` | General security invariants, fail-closed behavior |

### TIER 2: Encoding/Decoding Tests (90%+ coverage target) 📦

These tests ensure data flows correctly through the pipeline without corruption or leakage.

| Test File | What It Tests |
|-----------|---------------|
| `test_encode.py` | Full encoding pipeline, CLI args, output validation |
| `test_decode_gif.py` | GIF decoding, QR extraction, manifest parsing |
| `test_decode_gif_main.py` | Decode CLI entry point, error handling |
| `test_meow_encode.py` | Encode module integration |
| `test_qr_code.py` | QR code generation and reading |
| `test_gif_handler.py` | GIF creation, frame extraction, optimization |
| `test_config.py` | Configuration loading, saving, defaults |
| `test_spec_v12_encode.py` | Protocol v1.2 encoding compliance |
| `test_spec_v12_decode.py` | Protocol v1.2 decoding compliance |

### TIER 3: Advanced Features Tests (Best-effort coverage) 🧪

| Test File | What It Tests |
|-----------|---------------|
| `test_schrodinger_comprehensive.py` | Dual-secret quantum superposition encoding |
| `test_quantum_mixer_comprehensive.py` | Reality entanglement, statistical indistinguishability |
| `test_duress_mode.py` | Coercion-resistant decoy passwords |
| `test_timelock_duress.py` | Time-lock puzzles, dead-man's switch |
| `test_deadmans_switch_cli_comprehensive.py` | CLI for timed release features |
| `test_double_ratchet.py` | Signal-style double ratchet protocol |
| `test_multi_secret_comprehensive.py` | N-level plausible deniability (16+ secrets) |
| `test_stego_advanced.py` | LSB steganography, carrier images |
| `test_ninja_cat_ultra_comprehensive.py` | Maximum stealth encoding |
| `test_entropy_boost_comprehensive.py` | Multi-source entropy collection |
| `test_hardware_keys.py` | TPM 2.0, YubiKey, smart card support |
| `test_hardware_integration.py` | Hardware security module detection |
| `test_merkle_tree_comprehensive.py` | Merkle root integrity verification |
| `test_secure_cleanup.py` | Memory wiping, key destruction |
| `test_secure_bridge_comprehensive.py` | Rust-Python FFI security |

### TIER 4: Utility & UI Tests 🛠️

| Test File | What It Tests |
|-----------|---------------|
| `test_cat_utils_comprehensive.py` | Cat-themed utilities, Nine Lives retry |
| `test_catnip_fountain_comprehensive.py` | Catnip-flavored fountain codes |
| `test_progress_modules_comprehensive.py` | Progress bars, status indicators |
| `test_ascii_qr_comprehensive.py` | ASCII QR code rendering |
| `test_bidirectional_comprehensive.py` | Two-way communication protocols |
| `test_clowder_comprehensive.py` | Multi-device streaming (Clowder mode) |
| `test_logo_and_gui_comprehensive.py` | Logo-eyes carrier, GUI components |
| `test_dashboard_gui_comprehensive.py` | Dashboard interface |
| `test_webcam_modules_comprehensive.py` | Webcam capture, live decoding |
| `test_decoy_generator_comprehensive.py` | Convincing decoy file generation |
| `test_high_security_comprehensive.py` | Paranoid mode, ultra-hardened settings |
| `test_security_warnings_comprehensive.py` | Warning suppression, user alerts |
| `test_debug_modules_comprehensive.py` | Debug logging, verbose output |
| `test_prowling_mode_comprehensive.py` | Low-memory streaming mode |
| `test_streaming_crypto_comprehensive.py` | Large file streaming encryption |
| `test_resume_secured_comprehensive.py` | Encrypted resume/checkpoint files |
| `test_profiling_improved_comprehensive.py` | Performance profiling |

### TIER 5: Coverage Boost & Cat Error Tests 📈

Targeted tests added in February 2026 to reach 95% codecov:

| Test File | What It Tests |
|-----------|---------------|
| `test_coverage_boost_cat_utils.py` | PurrLogger, NineLivesRetry, CatBreed, aliases, sounds, ASCII art (66 tests) |
| `test_coverage_boost_spec_v12.py` | Spec v1.2 encode/decode, key management, steganography, multi-tier (28 tests) |
| `test_coverage_boost_catnip.py` | CatnipFountainEncoder/Decoder edge cases (10 tests) |
| `test_coverage_boost_schrodinger.py` | Schrödinger dual-reality encode/decode, manifest pack/unpack (18 tests) |
| `test_coverage_boost_remaining.py` | Prowling mode, streaming crypto, resume, profiling, ninja cat (67 tests) |
| `test_coverage_boost_extras.py` | Entropy boost, secure bridge, double ratchet, merkle tree, multi-secret (69 tests) |
| `test_cat_errors.py` | Cat-themed error system: exception hierarchy, fur_ball_error catalog, pounce_on_errors decorator, litter_box_cleanup, output helpers, cat_translate_error, meow_excepthook (40+ tests) |

### Roadmap Tests (ST + MT) 🗺️

| Test File | What It Tests |
|-----------|---------------|
| `test_manifest_bounds.py` | ST-2: Manifest numeric bounds, decompression-bomb protection, ephemeral pubkey validation (17 tests) |
| `test_canonical_aad.py` | MT-1: Canonical AAD construction, deterministic ordering, backward compat, roundtrip (10 tests) |
| `test_timing_harness.py` | MT-5: Statistical timing comparison for correct/wrong password, duress/real (varies) |
| `test_tamper_report.py` | MT-7: TamperReport class, ASCII timeline, cluster detection, JSON export (19 tests) |
| `test_bridge_protocol.py` | MT-8: Mobile bridge wire protocol, 6 message types, parser validation (21 tests) |

### Property-Based & Adversarial Tests 🎲

| Test File | What It Tests |
|-----------|---------------|
| `test_property_based.py` | Hypothesis-powered random input fuzzing |
| `test_adversarial.py` | Hostile inputs, attack simulation |

---

## 🎯 Goal #1: Prove the Code Actually Works Securely (Not Just "It Runs")

The primary job of these tests is to confirm that:

- The cryptography behaves **exactly** as it should — no secret leaks, no weak spots
- Forward secrecy (ratcheting keys) actually protects past messages if a key is compromised
- Plausible deniability (Schrödinger / duress modes) really works: an attacker can't tell which password is real vs. decoy
- Dead-man's switch / timelock duress triggers correctly without leaving forensic traces
- Constant-time operations in Rust actually prevent timing side-channels
- Errors are **uniform** (always say "Decryption failed" — never leak info like "wrong key" vs. "corrupt data")
- Bad/malformed/corrupted inputs are rejected safely (no crashes, no partial decodes, no info leaks)

We do **not** mainly test "happy paths" (everything works perfectly).  
We **ruthlessly** test failure modes, edge cases, and attacks because that's where real vulnerabilities hide.

---

## 🎯 Goal #2: Achieve High Branch Coverage on Risky Paths

We aim for **≥90% branch coverage** (measured with `coverage.py --branch`).

This means we try to execute **every possible decision point** in the code — especially the ones that could:

- Leak a key
- Reuse a nonce
- Fall back insecurely
- Fail to wipe memory
- Distinguish duress vs. normal decryption
- Allow forgery or replay

High branch coverage here is **not** about "clean code" — it's about making sure we've forced every security-critical `if`/`else`, `try`/`except`, and Rust–Python boundary to run at least once and behave correctly.

### Coverage Targets by Tier

| Tier | Modules | Target | Priority |
|------|---------|--------|----------|
| TIER 1 | crypto.py, crypto_backend.py, fountain.py, frame_mac.py, constant_time.py | 95-100% | Critical |
| TIER 2 | encode.py, decode_gif.py, config.py, qr_code.py, gif_handler.py | 90%+ | High |
| TIER 3 | Advanced features (Schrödinger, duress, PQ, stego) | 80%+ | Medium |
| TIER 4 | Utilities, UI, debug modules | Best-effort | Low |

---

## 🚫 What We Do NOT Care About (Much)

These tests are **not** trying to:

- Enforce style (PEP 8, black, flake8) → that's handled by linters/CI
- Check readability or maintainability → that's for code review
- Test documentation strings or type hints → separate tools
- Measure "code quality" in a general sense (cyclomatic complexity, etc.)

If the code is ugly but passes every adversarial test with zero security violations → it still passes the most important bar.

---

## 🧪 Types of Tests You'll See

| Test Type | Description | Example Files |
|-----------|-------------|---------------|
| **Property-based / fuzz-style** | Generates thousands of weird binary inputs, invalid keys, truncated streams | `test_property_based.py`, `test_adversarial.py` |
| **Fault injection** | Mock Rust panics, side-channel errors, or import failures | `test_crypto_backend.py`, `test_secure_bridge_comprehensive.py` |
| **Time mocking** | Jump forward/backward in time for timelock/duress tests | `test_timelock_duress.py`, `test_deadmans_switch_cli_comprehensive.py` |
| **Exception forcing** | Deliberately trigger errors to ensure uniform handling | `test_security.py`, `test_duress_mode.py` |
| **Rust–Python boundary** | Check that secrets don't leak across the FFI bridge | `test_crypto_backend.py`, `test_constant_time.py` |
| **Adversarial inputs** | Corrupted GIF frames, wrong headers, replayed nonces | `test_adversarial.py`, `test_frame_mac.py` |
| **Statistical tests** | Verify cryptographic indistinguishability | `test_quantum_mixer_comprehensive.py` |

---

## 🏃 Running the Tests

```bash
# Run all tests with coverage
pytest tests/ -v --cov=meow_decoder --cov-report=term-missing

# Run only security-critical tests (TIER 1)
pytest tests/test_crypto*.py tests/test_frame_mac.py tests/test_fountain.py tests/test_forward_secrecy*.py -v

# Run with HTML coverage report
pytest tests/ --cov=meow_decoder --cov-report=html
open htmlcov/index.html

# Run property-based tests with more examples
pytest tests/test_property_based.py -v --hypothesis-seed=0

# Run a specific test module
pytest tests/test_schrodinger_comprehensive.py -v

# Run tests matching a pattern
pytest tests/ -k "duress" -v
```

---

## 📋 Shared Fixtures (conftest.py)

The `tests/conftest.py` provides reusable fixtures:

| Fixture | Purpose |
|---------|---------|
| `random_salt` | 16-byte cryptographic salt |
| `random_nonce` | 12-byte AES-GCM nonce |
| `valid_password` | Valid password meeting length requirements |
| `temp_dir` | Temporary directory for test files |
| `sample_file` | Sample file for encoding tests |

---

## 👋 Why This Matters for New Contributors

If you're adding or changing code in crypto, forward secrecy, duress, encoding/decoding, or cleanup paths:

1. **Write tests first** (or at the same time) — especially for any new branch/decision
2. Focus on **what could go wrong** — not just "what works"
3. Run `pytest --cov=meow_decoder --cov-branch --cov-report=html` and look at uncovered branches
4. If a branch is security-relevant and uncovered → that's a red flag

The tests are paranoid by design.  
They treat every uncovered branch in critical code as a **potential vulnerability** until proven otherwise.

---

## 🦀 Rust Crypto Backend Tests

The project includes **261 Rust tests** across two packages:

### rust_crypto (meow_crypto_rs) - 151 tests

| File | Tests | Purpose |
|------|-------|--------|
| `src/pure.rs` | 46 | Pure Rust crypto: Argon2id, AES-GCM, HKDF, HMAC, SHA256, X25519, ML-KEM-768 |
| `tests/comprehensive_tests.rs` | 76 | Core crypto operations via PyO3 bindings |
| `tests/additional_security_tests.rs` | 29 | Security edge cases, zeroization, failure modes |
| `tests/proptest_crypto.rs` | 23 | Property-based fuzzing with random inputs |

### crypto_core - 110 tests (97.9% coverage)

| File | Tests | Purpose |
|------|-------|--------|
| `src/*.rs` (unit tests) | 89 | AEAD wrapper, nonce handling, types, verus proofs |
| `tests/coverage_tests.rs` | 47 | Edge case coverage tests |
| `tests/security_properties.rs` | 17 | Security property verification |
| `tests/core_smoke.rs` | 5 | Smoke tests for core functionality |

### Running Rust Tests

**Requirements:**
```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install test dependencies (for coverage)
cargo install cargo-tarpaulin
```

**Run commands:**
```bash
cargo test -p meow_crypto_rs    # PyO3 bindings (174 tests)
cargo test -p crypto_core       # Formally verified (158 tests)

# Coverage (crypto_core only - PyO3 blocks tarpaulin)
cargo tarpaulin -p crypto_core --skip-clean
```

---

## 📚 Related Documentation

- [TEST_SUITE_README.md](../tests/TEST_SUITE_README.md) - Implementation details
- [THREAT_MODEL.md](THREAT_MODEL.md) - What we're defending against
- [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) - Security properties we verify
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design

---

Welcome to meow-decoder — where "it works on my machine" is never good enough. 😼

Questions? Ask in issues or chat — we're all Cat Herders learning how to build tools that can actually resist real threats. 🐾

Found a vulnerability? Check the [🌿 Catnip Bounty Program (SECURITY.md)](../SECURITY.md).