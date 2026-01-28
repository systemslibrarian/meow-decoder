# 🔬 Meow Decoder Fuzzing

This directory contains fuzzing harnesses for Meow Decoder, using [AFL++](https://aflplus.plus/) via Python bindings ([atheris](https://github.com/google/atheris)).

Fuzzing helps identify edge cases, parsing errors, and potential crashes that standard unit tests might miss.

## Prerequisites

You need `atheris` installed. It works best on Linux/macOS.

```bash
pip install atheris
```

## Running Fuzzers

Each script functions as a standalone fuzzer target.

### 1. Fuzz Manifest Parsing

Tests `SchrodingerManifest.unpack()` against malformed binary data.

```bash
# Run for 100,000 runs or until crash
python3 fuzz/fuzz_manifest.py -runs=100000
```

### 2. Fuzz Crypto Operations

Tests key derivation and decryption error handling.

```bash
python3 fuzz/fuzz_crypto.py -runs=100000
```

### 3. Fuzz Fountain Codes

Tests droplet unpacking and fountain decoding logic.

```bash
python3 fuzz/fuzz_fountain.py -runs=100000
```

## Corpus

The `seed_corpus.py` script generates valid seed inputs to help the fuzzer start from a good state.

```bash
# Generate corpus (if needed)
python3 fuzz/seed_corpus.py
```

## Findings

*   **2024-01-25**: Historical note (unverified in current repo). Do not rely on this without a recorded run log.
*   *Add new findings here.*
