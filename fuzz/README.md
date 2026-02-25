# 🔬 Meow Decoder Fuzzing

This directory contains **21 Python Atheris fuzzing harnesses** + 1 AFL++ target for Meow Decoder, using [AFL++](https://aflplus.plus/) via Python bindings ([atheris](https://github.com/google/atheris)).

Fuzzing helps identify edge cases, parsing errors, and potential crashes that standard unit tests might miss.

## Test Coverage

The fuzzing infrastructure includes **1448 lines of comprehensive tests** (`tests/test_fuzz_targets.py`) with **95%+ code coverage**:

| Test Class | Tests | Description |
|------------|-------|-------------|
| `TestFuzzManifest` | 18 | Manifest parsing: MEOW2/3/4, forward secrecy, duress, PQ mode |
| `TestFuzzCrypto` | 24 | Key derivation, decryption, HMAC verification, NIST enforcement |
| `TestFuzzFountain` | 18 | Droplet unpacking, fountain decoding, belief propagation |
| `TestAflFuzzManifest` | 3 | AFL persistence mode, crash-on-failure |
| `TestSeedCorpus` | 13 | Corpus generation, CLI interface, idempotency |
| `TestFuzzIntegration` | 5 | Cross-module, mutation resilience, stress testing |
| `TestFuzzErrorHandling` | 4 | Error handling verification per module |
| `TestFuzzCoverageGaps` | 10 | Edge cases for exception paths, NIST enforcement |
| `TestFuzzMockedExceptions` | 16 | Mocked exception handling for full coverage |
| `TestAtherisInstrumentation` | 8 | Module setup and imports |
| `TestAtherisInstrumentedPaths` | 3 | Atheris instrumentation via module reload |
| **Total** | **122** | Full harness validation |

### Coverage by Module

| Module | Coverage |
|--------|----------|
| `fuzz_crypto.py` | 95.29% |
| `fuzz_manifest.py` | 98.11% |
| `fuzz_fountain.py` | 98.48% |
| `fuzz_windows_guard.py` | NEW (8 fuzz functions) |
| `fuzz_mouse_gesture.py` | NEW (10 fuzz functions) |
| `fuzz_tamper_detection.py` | NEW (10 fuzz functions) |
| `fuzz_adversarial_stego.py` | NEW (10 fuzz functions, differential) |
| `fuzz_x25519_fs.py` | NEW (4 fuzz functions, DH key agreement) |
| `fuzz_timelock_expiry.py` | NEW (5 fuzz functions, time-lock + expiry) |
| `fuzz_forensic_cleanup.py` | NEW (2 fuzz functions, artifact cleanup) |
| `seed_corpus.py` | 100% |
| `afl_fuzz_manifest.py` | 100% |

Run the test suite:

```bash
pytest tests/test_fuzz_targets.py -v
```

## Prerequisites

You need `atheris` installed. It works best on Linux/macOS.

```bash
pip install atheris
```

## Running Fuzzers

Each script functions as a standalone fuzzer target.

### 1. Fuzz Manifest Parsing

Tests `SchrodingerManifest.unpack()` and `crypto.unpack_manifest()` against malformed binary data.

```bash
# Run for 100,000 runs or until crash
python3 fuzz/fuzz_manifest.py -runs=100000

# AFL++ mode (persistent)
python3 fuzz/afl_fuzz_manifest.py
```

### 2. Fuzz Crypto Operations

Tests key derivation (with NIST 8-char minimum enforcement) and decryption error handling.

```bash
python3 fuzz/fuzz_crypto.py -runs=100000
```

### 3. Fuzz Fountain Codes

Tests droplet unpacking and fountain decoding logic.

```bash
python3 fuzz/fuzz_fountain.py -runs=100000
```

### 4. Fuzz Guard Page Memory Safety

Tests `GuardedBuffer` write/read bounds, double-free, use-after-free, concurrent alloc/free, and guard page activation.

```bash
python3 fuzz/fuzz_windows_guard.py -runs=100000
```

### 5. Fuzz Mouse Gesture Auth

Tests `MouseGesturePassword` quantization determinism, BLAKE2b derivation with person tag, grid size variation, perturbation stability, and collision resistance.

```bash
python3 fuzz/fuzz_mouse_gesture.py -runs=100000
```

### 6. Fuzz Tamper Detection

Tests `TamperState` serialization roundtrip, HMAC checkpoint integrity, silent poison determinism/uniqueness, and `TamperDetector` with fake modules.

```bash
python3 fuzz/fuzz_tamper_detection.py -runs=100000
```

### 7. Fuzz Adversarial Stego Rotation (Differential)

Differential fuzzing of adversarial carrier noise generators. Verifies sensor/texture/DCT/combined produce distinct noise for the same seed, checks rotation schedule coverage, histogram equalization, and noise profile extremes.

```bash
python3 fuzz/fuzz_adversarial_stego.py -runs=100000
```

### 8. Fuzz X25519 Forward Secrecy

Tests X25519 key agreement, ephemeral key derivation, HKDF domain separation, and shared-secret computation with malformed keys.

```bash
python3 fuzz/fuzz_x25519_fs.py -runs=100000
```

### 9. Fuzz Time-Lock Duress & Content Expiry

Tests time-lock puzzle construction, duress trigger timing, content expiry enforcement, and edge cases (zero TTL, overflow timestamps).

```bash
python3 fuzz/fuzz_timelock_expiry.py -runs=100000
```

### 10. Fuzz Forensic Cleanup

Tests artifact cleanup routines to ensure no sensitive data persists after file/memory wipe operations.

```bash
python3 fuzz/fuzz_forensic_cleanup.py -runs=100000
```

## Corpus Generation

The `seed_corpus.py` script generates valid seed inputs to help the fuzzer start from a good state.

```bash
# Generate corpus to default directory
python3 fuzz/seed_corpus.py

# Generate to specific directory
python3 fuzz/seed_corpus.py --output /path/to/corpus

# AFL-compatible manifest corpus
python3 fuzz/seed_corpus.py --afl --manifest-only --output afl_corpus/
```

### Seed Types Generated

- **Manifest samples**: Valid MEOW2/3/4 structures with mutations
- **Crypto samples**: Salt + password combinations, edge cases
- **Fountain samples**: Droplet structures, boundary cases
- **Edge cases**: Empty files, single bytes, max-length data

## Security Properties Tested

The fuzzing infrastructure validates:

1. **No crashes on arbitrary input** - All harnesses must handle any byte sequence
2. **NIST password compliance** - 8-character minimum enforced in key derivation
3. **Manifest version handling** - MEOW2, MEOW3 (forward secrecy), MEOW4/MEOW5 (post-quantum)
4. **Bit-flip resilience** - Random mutations don't cause undefined behavior
5. **Length extension immunity** - Extended data handled gracefully
6. **Cross-module consistency** - Same data produces consistent behavior
7. **Guard page memory isolation** - OOB write/read traps, double-free safety, use-after-free detection
8. **Gesture auth quantization stability** - Deterministic quantization, BLAKE2b domain separation, grid cell stability
9. **Tamper checkpoint HMAC integrity** - Corrupt/truncated state rejected, silent poison determinism
10. **Stego rotation differential** - All 4 algorithms produce distinct noise, schedule coverage, carrier noise in valid range

### Formal Complement: GuardedBuffer / `SecureBox`

The `fuzz_memory_guard.py` harness stress-tests `memory_guard.py`'s Python wrapper.
The underlying `SecureBox` allocator in **`crypto_core/src/secure_alloc.rs`** is
also covered by **real `verus!{}` proofs** in `crypto_core/src/verus_guarded_buffer.rs`:

| Property | Fuzz coverage | Verus proof |
|----------|---------------|-------------|
| Guard-page layout invariant | `fuzz_memory_guard.py` | GB-001 `lemma_guard_layout_established` |
| Overflow → upper guard fault | extreme-size corpus | GB-002 `lemma_overflow_hits_upper_guard` |
| Underflow → lower guard fault | edge-case allocations | GB-003 `lemma_underflow_hits_lower_guard` |
| Zeroize-on-drop | double-free harness | GB-007 `lemma_zeroize_erases_data` |

The Verus specification annotations provide **structural regression tracking** that
complements the probabilistic coverage from fuzzing. Note: the CI job performs
grep-based structural checks, not Z3/SMT verification (see `SECURITY_INVARIANTS.md` v1.3).

## Findings

- **2026-02-25**: Added 3 new fuzz targets closing audit gaps: X25519 forward secrecy (4 functions), time-lock duress + content expiry (5 functions), forensic cleanup (2 functions). All 3 added to `fuzz.yml` CI workflow. Total Python Atheris harnesses: **21** (+ 1 AFL++). Total fuzz targets across all languages: **31** (21 Python Atheris + 1 AFL++ + 9 Rust cargo-fuzz).
- **2026-02-22**: Added 4 new fuzz targets: guard page memory safety (8 functions), mouse gesture auth (10 functions), tamper detection (10 functions), adversarial stego differential (10 functions). Added integration tests (`tests/test_fuzz_coverage_integration.py`, 38 tests). Added Tamarin Schrödinger deniability model (`formal/tamarin/MeowSchrodingerDeniability.spthy`, 10 lemmas). Updated `SECURITY_INVARIANTS.md` with INV-033 through INV-037.
- **2026-01-28**: Comprehensive test suite added (85 tests, 821 lines)
- **2026-01-25**: AFL++ integration and seed corpus generation

## CI Integration

Fuzzing runs automatically in CI via GitHub Actions (`.github/workflows/fuzz.yml`):

- Weekly scheduled deep fuzzing (Sundays)
- Crash artifacts uploaded automatically
- Coverage reports generated
