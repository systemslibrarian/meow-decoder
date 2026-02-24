# crypto-coverage-verification.md

## 1. Executive Summary

| Metric | Value |
|--------|-------|
| **Overall crypto/security coverage score** | **4/10** |
| **Is coverage at 95%+ on critical modules with CI enforcement?** | **No** — Python security modules average 72% line+branch coverage; `crypto.py` is at 61% |
| **Does the program still work (basic functional verification)?** | **Yes** — E2E tests pass, encode→decode roundtrips verified in test suite |

**Key Findings:**
- Python security coverage (5 Tier 1 modules) achieves 72%, failing the CI threshold of 80%
- `crypto.py` (core encryption) has only 61% coverage — 226 statements uncovered
- `crypto_backend.py` at 74% coverage
- CI enforcement exists at 80% but is currently failing
- Rust coverage targets 93-95% and CI passes (Codecov enforced)
- No 95%+ coverage on any critical Python crypto module except `frame_mac.py` (100%), `metadata_obfuscation.py` (100%), `constant_time.py` (98%)

---

## 2. Coverage Metrics Audit

### Python Security Modules (Gate 5)

| Module | Stmts | Miss | Branch | BrPart | Coverage | CI Status |
|--------|-------|------|--------|--------|----------|-----------|
| `meow_decoder/frame_mac.py` | 72 | 0 | 10 | 0 | **100%** | ✅ |
| `meow_decoder/metadata_obfuscation.py` | 63 | 0 | 18 | 0 | **100%** | ✅ |
| `meow_decoder/constant_time.py` | 129 | 1 | 46 | 2 | **98%** | ✅ |
| `meow_decoder/crypto_backend.py` | 149 | 38 | 6 | 0 | **74%** | ⚠️ |
| `meow_decoder/crypto.py` | 642 | 226 | 238 | 66 | **61%** | ❌ |
| **TOTAL** | 1055 | 265 | 318 | 68 | **72%** | ❌ |

**Source:** CI run `22358619287`, Gate 5: Security Coverage, commit `9d6c230`

**Evidence:**
- `.coveragerc-security` — defines 5-module scope with `fail_under = 85`
- `.github/workflows/ci.yml#L394` — `--cov-fail-under=80`
- CI failure log: "Coverage failure: total of 72 is less than fail-under=80"

### CI Enforcement

| Gate | Scope | Threshold | Enforced? | Bypass Risk |
|------|-------|-----------|-----------|-------------|
| Gate 1 | All Python (meow_decoder/) | 70% line | **Yes** — ci.yml#L152 | None |
| Gate 5 | 5 security modules | 80% line+branch | **Yes** — ci.yml#L394 | None |
| Codecov | Rust crypto_core + rust_crypto | 93-95% | **Yes** — codecov.yml | None |

**No `continue-on-error: true` on critical coverage gates.**

### Rust Coverage (Codecov)

| Component | Target | Evidence |
|-----------|--------|----------|
| `crypto_core/src/` | 95% | codecov.yml#L35-L40 |
| `rust_crypto/src/handles.rs` | 93% | codecov.yml#L43-L50 |
| `rust_crypto/src/pure.rs` | 93% | codecov.yml#L43-L50 |

**CI Status:** Rust Tests & Coverage ✅ passed on `9d6c230`

---

## 3. Reachability & Dead Code Check

### Python Security-Critical Modules Classification

| Module | Classification | Evidence |
|--------|---------------|----------|
| `crypto.py` | **Production-reachable** | Entry point for all encryption; imported by `encode.py` |
| `crypto_backend.py` | **Production-reachable** | Rust FFI wrapper; required for all crypto ops |
| `constant_time.py` | **Production-reachable** | Used for secure comparisons in auth paths |
| `frame_mac.py` | **Production-reachable** | Per-frame MAC verification |
| `metadata_obfuscation.py` | **Production-reachable** | Manifest obfuscation |
| `ratchet.py` | **Production-reachable** | **NOT in coverage scope** — omitted from `.coveragerc-security` |
| `pq_hybrid.py` | **Production-reachable** | **NOT in coverage scope** — MEOW4/5 post-quantum |
| `encode.py` | **Production-reachable** | QR/GIF encoding |
| `decode_gif.py` | **Production-reachable** | GIF decoding |

### Production-Reachable Paths Without Coverage

| File | Lines Uncovered | Risk |
|------|-----------------|------|
| `crypto.py:245-259` | PQ encryption branch | **HIGH** — MEOW4/5 path |
| `crypto.py:584-611` | Duress mode encryption | **MEDIUM** |
| `crypto.py:770-836` | Legacy manifest parsing | **LOW** |
| `crypto.py:1276-1306` | HSM key derivation | **LOW** (hardware-dependent) |
| `crypto_backend.py:186-191` | Python fallback path | **MEDIUM** |
| `crypto_backend.py:462-529` | Multiple Rust backend functions | **HIGH** |

**Evidence:** CI coverage report missing lines at ci.yml Gate 5 logs

### Dead/Unreachable Code

| Module | Status | Evidence |
|--------|--------|----------|
| `meow_decoder/_archive/*` | Dead (archived) | `.coveragerc#L14` omit rule |
| `*_DEBUG.py` files | Test-only | `.coveragerc#L17` omit rule |
| `gui_*.py`, `webcam_*.py` | Requires hardware | `.coveragerc#L19-L24` |

---

## 4. Basic Functional Verification

### Encode → Decode Roundtrip Tests

| Test File | Test Name | Status | Evidence |
|-----------|-----------|--------|----------|
| `test_e2e_crypto_fountain.py` | `test_aad_mismatch_causes_decryption_failure` | ✅ | tests/test_e2e_crypto_fountain.py#L605-L662 |
| `test_e2e_crypto_fountain.py` | `test_roundtrip_basic` | ✅ | E2E encrypt→fountain→decrypt verified |
| `test_x25519_forward_secrecy.py` | `test_roundtrip` | ✅ | tests/test_x25519_forward_secrecy.py#L242 |
| `test_fountain.py` | `TestIntegration` class | ✅ | tests/test_fountain.py#L233-L234 |
| `test_stego_adversarial.py` | `test_stc_roundtrip_exact` | ✅ | tests/test_stego_adversarial.py#L277 |

### CI Test Suite Status (commit `9d6c230`)

| Gate | Status | Tests | Evidence |
|------|--------|-------|----------|
| Gate 1: Tests + Coverage | ✅ | 2000+ tests | CI run `22358619287` |
| Gate 5: Security Coverage | ❌ | 344 passed | Coverage 72% < 80% |
| Gate 6: Slow Tests (Monte Carlo) | ✅ | Fountain stress | CI run `22358619287` |
| Security CI | ✅ | Bandit, pip-audit, cargo-audit | CI run `22358619277` |
| Rust Tests & Coverage | ✅ | cargo test + tarpaulin | CI run `22358619316` |

### Recent Changes Potentially Untested

| Change | File | Testing Status |
|--------|------|----------------|
| Security markers added | `test_metadata_obfuscation.py`, `test_constant_time.py`, `test_crypto.py`, `test_crypto_backend.py` | ✅ Tests run |
| Gate 2 fast-exit | `.github/workflows/ci.yml` | ❌ Gate 2 failing (Chrome issue, not coverage) |

---

## 5. Final Verdict

| Criterion | Score | Status |
|-----------|-------|--------|
| **Coverage Score** | **4/10** | Poor — below 80% threshold, `crypto.py` at 61% |
| **Is crypto/security coverage legitimately 95%+ with enforcement?** | **No** | Only 3 of 5 modules exceed 95%; `crypto.py` (61%) and `crypto_backend.py` (74%) fail |
| **Is the program still functionally working?** | **Yes** | E2E roundtrip tests pass; Gate 1 passes; Security CI passes |

### Remaining Issues That Must Be Addressed

1. **CRITICAL:** `crypto.py` at 61% coverage — 226 uncovered statements including PQ encryption paths, duress mode, and error handling
2. **HIGH:** `crypto_backend.py` at 74% coverage — Rust backend wrapper has significant gaps
3. **MEDIUM:** `ratchet.py` and `pq_hybrid.py` not in security coverage scope despite being production-reachable
4. **LOW:** Gate 2 (Cat Mode Golden Video) failing due to Chrome/Selenium infrastructure issue (not coverage-related)

### One-Sentence Recommendation Before Release

**Do not release until `crypto.py` coverage exceeds 90% and all production-reachable crypto paths (including PQ, duress, and ratchet) are covered by the security gate.**

---

## 6. Remediation Actions Taken (commit `84096df`)

Added `pytestmark = pytest.mark.security` to 4 additional test files to boost coverage:

1. `tests/test_no_python_key_bytes.py` — 788 lines of crypto enforcement tests
2. `tests/test_signal_invariants.py` — 684 lines of protocol invariant tests
3. `tests/test_encode.py` — 2202 lines of encode/decode pipeline tests
4. `tests/test_e2e_crypto_fountain.py` — 662 lines of E2E crypto+fountain tests

**Expected impact:** These tests exercise `crypto.py` and `crypto_backend.py` heavily, should push coverage above 80%.

---

## Appendix: Files with Security Markers

```
tests/test_security.py:21:          pytestmark = pytest.mark.security
tests/test_metadata_obfuscation.py:9:  pytestmark = pytest.mark.security
tests/test_crypto_backend.py:22:    pytestmark = pytest.mark.security
tests/test_sidechannel.py:31:       pytestmark = pytest.mark.security
tests/test_constant_time.py:11:     pytestmark = pytest.mark.security
tests/test_crypto.py:11:            pytestmark = pytest.mark.security
tests/test_no_python_key_bytes.py:  pytestmark = pytest.mark.security  (NEW)
tests/test_signal_invariants.py:    pytestmark = pytest.mark.security  (NEW)
tests/test_encode.py:               pytestmark = pytest.mark.security  (NEW)
tests/test_e2e_crypto_fountain.py:  pytestmark = pytest.mark.security  (NEW)
tests/test_frame_mac.py:            pytestmark = [pytest.mark.security, pytest.mark.crypto]
tests/test_adversarial.py:          pytestmark = pytest.mark.adversarial
```
