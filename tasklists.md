# 🐾 Meow Decoder — Roadmap Task List

> Last updated: 2026-02-06
> Status legend: `[ ]` not started · `[~]` in progress · `[x]` completed

---

## Short-Term (1–2 weeks, Low–Medium Effort)

### ST-1: Remove/quarantine duplicate crypto paths
- **Effort:** Medium (~2–4 hours)
- **Dependencies:** None
- **Status:**
  - [ ] Create `meow_decoder/experimental/` package with `__init__.py`
  - [ ] Move `forward_secrecy_x25519.py` → `experimental/`
  - [ ] Move `x25519_forward_secrecy.py` → `experimental/`
  - [ ] Move `crypto.py` (legacy) → `experimental/` if fully superseded
  - [ ] Move `*_DEBUG.py` files → `experimental/`
  - [ ] Verify CLI and default imports use only consolidated primary path (`crypto_enhanced.py` + Rust `crypto_core`)
  - [ ] Update all cross-module imports
  - [ ] Add `experimental/README.md` deprecation notice

### ST-2: Manifest numeric bounds + decompression-bomb protection
- **Effort:** Medium (~2–3 hours)
- **Dependencies:** None
- **Status:**
  - [ ] Add strict bounds checking in `unpack_manifest()` for `orig_len`, `comp_len`, `cipher_len`, `block_size`, `k_blocks`
  - [ ] Add ephemeral pubkey validation (32 bytes, not all-zero)
  - [ ] Add PQ ciphertext length validation (1088 bytes if present)
  - [ ] Add decompression output limit: `orig_len × MAX_DECOMP_RATIO` (e.g. 10×)
  - [ ] Add tests for each boundary violation
  - [ ] Add tests for decompression bomb rejection

### ST-3: Fix memory zeroing claims
- **Effort:** Low (~1 hour)
- **Dependencies:** None
- **Status:**
  - [ ] Audit all Python docs/comments claiming memory zeroing → change to "best-effort"
  - [ ] Audit all Rust docs/comments → confirm "guaranteed via zeroize crate"
  - [ ] Update THREAT_MODEL.md, SECURITY.md, and architecture docs
  - [ ] Update inline code comments in `crypto_enhanced.py`, `constant_time.py`, `cat_errors.py`

### ST-4: Define pytest markers + --strict-markers
- **Effort:** Low (~30 minutes)
- **Dependencies:** None
- **Status:**
  - [ ] Add marker definitions in `pyproject.toml`: `security`, `adversarial`, `crypto`, `fuzz`, `slow`
  - [ ] Enable `--strict-markers` in `pyproject.toml` `[tool.pytest.ini_options]`
  - [ ] Add `@pytest.mark.*` decorators to existing test modules
  - [ ] Verify `pytest --co` succeeds with strict markers enabled

### ST-5: Gate PRs with security coverage ≥ 85–90%
- **Effort:** Low (~1 hour)
- **Dependencies:** ST-4
- **Status:**
  - [ ] Create `.coveragerc-security` targeting only TIER 1 crypto modules
  - [ ] Add CI step: `pytest --cov-config=.coveragerc-security --cov-fail-under=85`
  - [ ] Document in CONTRIBUTING.md

### ST-6: Add `--self-test` CLI command
- **Effort:** Low–Medium (~1–2 hours)
- **Dependencies:** None
- **Status:**
  - [ ] Add `--self-test` flag to `encode.py` CLI (argparse)
  - [ ] Implement encrypt/decrypt roundtrip verification
  - [ ] Verify backend selection (Rust vs Python)
  - [ ] Print pass/fail results with cat flair
  - [ ] Add test for `--self-test` in `test_cli.py`

### ST-7: Benchmark Argon2id on low-end hardware
- **Effort:** Low (~30 minutes, docs only)
- **Dependencies:** None
- **Status:**
  - [ ] Document Argon2id params (64 MiB, 3 iter, 4 threads)
  - [ ] Add expected timing benchmarks for Raspberry Pi 4 / low-end VPS
  - [ ] Add adjustment guidance if >5s on target hardware
  - [ ] Add to docs/USAGE.md or docs/ARCHITECTURE.md

### ST-8: Complete CLI wiring for HSM/YubiKey
- **Effort:** Medium (~2–3 hours)
- **Dependencies:** Existing `hardware_integration.py`
- **Status:**
  - [ ] Wire `--hsm-slot`, `--hsm-pin`, `--hsm-key-label` in encode CLI
  - [ ] Wire same flags in decode CLI
  - [ ] Wire `--tpm-derive` flag
  - [ ] Wire `--hardware-auto` flag
  - [ ] Add integration tests (mocked HSM/TPM)
  - [ ] Document in docs/USAGE.md

---

## Medium-Term (1–3 months, Medium–High Effort)

### MT-1: Canonical AAD construction
- **Effort:** High (~4–6 hours)
- **Dependencies:** ST-1
- **Status:**
  - [ ] Define canonical AAD = `version_byte || fixed-order manifest fields`
  - [ ] Update `encrypt_file_bytes()` and `decrypt_to_raw()` to use canonical AAD
  - [ ] Add backward compatibility for existing MEOW2/MEOW3 manifests
  - [ ] Add test vectors

### MT-2: Lock down CI — enforce 3 PR gates
- **Effort:** Medium (~2 hours)
- **Dependencies:** ST-4, ST-5
- **Status:**
  - [ ] Gate 1: Fast pytest (no slow marker)
  - [ ] Gate 2: Security coverage ≥ 85%
  - [ ] Gate 3: Lint + type check (flake8, mypy, black)
  - [ ] All gates required for merge

### MT-3: Codecov — fail only on main push
- **Effort:** Low (~30 minutes)
- **Dependencies:** None
- **Status:**
  - [ ] Update `codecov.yml` to fail checks only on `push` to `main`, not on PRs

### MT-4: Remove continue-on-error from security-ci.yml
- **Effort:** Low (~15 minutes)
- **Dependencies:** MT-2
- **Status:**
  - [ ] Audit `security-ci.yml` for `continue-on-error: true`
  - [ ] Remove or justify each instance

### MT-5: Basic timing attack test harness
- **Effort:** Medium (~2–3 hours)
- **Dependencies:** ST-4
- **Status:**
  - [ ] Create `tests/test_timing_harness.py` with `@pytest.mark.security`
  - [ ] Statistical timing comparison for correct vs wrong password
  - [ ] Statistical timing comparison for duress vs real
  - [ ] Configurable threshold + skip on inconsistent CI runners

### MT-6: Expand opsec docs → Secure Usage Checklist
- **Effort:** Low–Medium (~1–2 hours)
- **Dependencies:** None
- **Status:**
  - [ ] Create `docs/SECURE_USAGE_CHECKLIST.md`
  - [ ] Cover: power off after use, secure delete temp files, screen recording risks, OS hardening recommendations, camera security
  - [ ] Link from README, QUICKSTART, THREAT_MODEL

### MT-7: Tamper timeline visualization
- **Effort:** Medium (~2–3 hours)
- **Dependencies:** None
- **Status:**
  - [ ] Add `--tamper-report` flag to decode CLI
  - [ ] Output frame-by-frame MAC verification results
  - [ ] Generate ASCII or HTML timeline of pass/fail frames
  - [ ] Highlight suspicious patterns (clustered failures)

### MT-8: Minimal CLI → React Native QR/video scanner bridge
- **Effort:** High (~1–2 weeks)
- **Dependencies:** All short-term items
- **Status:**
  - [ ] Define JSON/protobuf wire protocol between phone and CLI
  - [ ] Create minimal React Native camera → QR scanner component
  - [ ] Phone sends raw QR data to CLI over local network / USB
  - [ ] Phone stays "dumb" — no crypto on device
  - [ ] Document architecture in `mobile/ARCHITECTURE.md`

---

## Notes

- **Primary crypto path:** `crypto_enhanced.py` (Python) + `crypto_core/` (Rust)
- **Experimental directory:** `meow_decoder/experimental/` for deprecated/duplicate code
- **Test count:** 68+ Python test modules + 332 Rust tests
- **Coverage target:** 95% overall, 85–90% TIER 1 security gate

---

*🐾 "Every task is a paw print on the path to production." — The Cat*
