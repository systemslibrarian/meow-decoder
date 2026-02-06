# Argon2id Parameter Benchmarks & Tuning Guide

> **Last updated:** 2026-02  
> **Applies to:** Meow Decoder v3.x (MEOW3/MEOW4 manifests)

## Current Parameters

| Parameter        | Production            | Test Mode (`MEOW_TEST_MODE=1`) |
|------------------|-----------------------|--------------------------------|
| **Memory**       | 512 MiB (524288 KiB)  | 32 MiB (32768 KiB)             |
| **Iterations**   | 20 passes             | 1 pass                         |
| **Parallelism**  | 4 threads             | 1 thread                       |
| **Key length**   | 32 bytes (256 bits)   | 32 bytes                       |
| **Salt length**  | 16 bytes (128 bits)   | 16 bytes                       |

These are set in `meow_decoder/crypto.py` lines 29-38.

## Why These Values?

### OWASP Comparison

The [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id) recommends:

| Param       | OWASP Minimum  | Meow Production | Multiplier |
|-------------|----------------|-----------------|------------|
| Memory      | 64 MiB         | 512 MiB         | **8×**     |
| Iterations  | 3 passes       | 20 passes       | **6.7×**   |
| Parallelism | 4 threads      | 4 threads       | 1×         |

We intentionally exceed OWASP by a large margin because:
- Meow Decoder protects **files at rest**, not web login passwords
- Users derive keys infrequently (once per encode/decode)
- Air-gap scenario means adversaries have unlimited offline time
- 5–10 seconds per key derivation is acceptable for file encryption

### Security Margin vs. Brute Force

With 512 MiB × 20 iterations:
- An attacker with 1 GPU (~16 GB VRAM) can test ~30 passwords/min
- A 4-word passphrase (diceware, ~51 bits) would take **~70,000 years** on one GPU
- Even a well-funded attacker with 1,000 GPUs: **~70 years**
- Standard 8-char random password (~52 bits): comparable security

## Expected Timing on Hardware Tiers

| Hardware Class              | RAM    | CPU/Cores     | Est. Time (Production) |
|-----------------------------|--------|---------------|------------------------|
| **Raspberry Pi 4**          | 4 GB   | Cortex-A72 ×4 | 15–30 seconds          |
| **Low-end laptop** (2020)   | 8 GB   | i5-1035G1 ×4  | 5–10 seconds           |
| **Mid-range desktop** (2023)| 16 GB  | Ryzen 5 5600  | 3–6 seconds            |
| **High-end workstation**    | 64 GB  | Ryzen 9 7950X | 1–3 seconds            |
| **CI / GitHub Actions**     | 7 GB   | 2 vCPUs       | 8–15 seconds           |

> **Note:** Actual times depend on memory bandwidth, not just CPU speed. Argon2id is
> deliberately memory-hard to resist GPU/ASIC attacks.

## Low-End Hardware Guidance

If encoding/decoding on a Raspberry Pi or similar constrained device is too slow,
you have two options:

### Option A: Reduce Parameters (Lower Security)

Set environment variables before running:

```bash
# Balanced parameters for low-end devices (~3-5 seconds)
export MEOW_ARGON2_MEMORY=131072     # 128 MiB
export MEOW_ARGON2_ITERATIONS=5      # 5 passes
export MEOW_ARGON2_PARALLELISM=2     # 2 threads
```

> **⚠️ WARNING:** Reducing parameters weakens brute-force resistance.
> At 128 MiB × 5 iterations, an attacker with 1 GPU can test ~500 passwords/min.
> Use a **strong passphrase** (≥6 diceware words / ≥72 bits) to compensate.

### Option B: Use a Keyfile (Recommended)

Add a 256-bit keyfile to eliminate password-guessing attacks entirely:

```bash
# Generate a random keyfile
dd if=/dev/urandom of=meow.key bs=32 count=1
# Encode with keyfile
meow-encode -i secret.pdf -o secret.gif -p "password" -k meow.key
```

With a keyfile, Argon2id parameters matter less since the key material is
already high-entropy.

## Test Mode

For CI and development, set `MEOW_TEST_MODE=1` to use fast parameters:

```bash
MEOW_TEST_MODE=1 pytest tests/ -v
```

Test mode uses 32 MiB × 1 iteration (~0.05–0.1 seconds), which is **not secure**
for production use but allows fast test runs.

## Changing Parameters

If you modify the Argon2id parameters in `crypto.py`:

1. **Backward compatibility:** Old manifests store the salt but not the Argon2id
   params. Changing production params means old encrypted files cannot be decoded
   unless the code retains the old params as a fallback.
2. **Test backward compat:** Run `tests/test_crypto.py::TestEncryptDecryptRoundtrip`
   after any change.
3. **Update this file** with new benchmark numbers.
4. **Update CHANGELOG.md** noting the parameter change.

## References

- [RFC 9106 – Argon2](https://www.rfc-editor.org/rfc/rfc9106)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [argon2-cffi documentation](https://argon2-cffi.readthedocs.io/)
- Biryukov, Dinu, Khovratovich. "Argon2: New Generation of Memory-Hard Functions" (2016)
