# 🔬 Meow Decoder Fuzzing

This directory contains fuzzing harnesses for Meow Decoder, using [AFL++](https://aflplus.plus/) via Python bindings ([atheris](https://github.com/google/atheris)).

Fuzzing helps identify edge cases, parsing errors, and potential crashes that standard unit tests might miss.

## Test Coverage

The fuzzing infrastructure includes **1362 lines of comprehensive tests** (`tests/test_fuzz_targets.py`) with **95%+ code coverage**:

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

## Findings

- **2026-01-28**: Comprehensive test suite added (85 tests, 821 lines)
- **2026-01-25**: AFL++ integration and seed corpus generation
- *Add new findings here.*

## CI Integration

Fuzzing runs automatically in CI via GitHub Actions (`.github/workflows/fuzz.yml`):

- Weekly scheduled deep fuzzing (Sundays)
- Crash artifacts uploaded automatically
- Coverage reports generated
