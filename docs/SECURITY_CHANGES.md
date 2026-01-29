# Security Hardening Changes (v1.0 Review)

**Date**: 2026-01-28  
**Review Reference**: `CRYPTO_SECURITY_REVIEW.md`  
**Verification Status**: All Phase 1 HIGH/MEDIUM findings addressed

---

## Summary

This document tracks security-related changes made in response to the comprehensive
cryptographic security review (`CRYPTO_SECURITY_REVIEW.md`). Changes are organized
by finding ID and include verification notes.

---

## Phase 1: Critical & High Severity Fixes

### CRIT-01: Post-Quantum Feature Gate Enforcement

**Finding**: Post-quantum libraries at v0.1.0-rc (release candidate) could accidentally
become default features, exposing users to unstable crypto primitives.

**Resolution**: Added CI job to `.github/workflows/security-ci.yml` that:
1. Verifies `pq-crypto` is NOT in default features
2. Checks for transitive dependencies that might pull in PQ crypto
3. Fails CI if PQ primitives leak into defaults

**Verification**:
```bash
grep -A5 "pq-feature-gate:" .github/workflows/security-ci.yml
```

**Status**: ✅ RESOLVED

---

### CRIT-02: Frame MAC Security Documentation

**Finding**: 8-byte truncated frame MAC insufficient for long-term authentication.

**Resolution**: **Already adequately documented**. The `frame_mac.py` module contains
50+ lines of security design rationale explaining:
- Frame MACs are for **DoS resistance only**, not long-term authentication
- Threat model explicitly excludes long-term authentication (manifest HMAC handles that)
- Birthday bound analysis justifying 64-bit truncation
- Layered defense architecture (frame MAC + manifest HMAC + AES-GCM)

**Key Documentation** (frame_mac.py lines 1-50):
```python
PURPOSE:
    DoS resistance - reject invalid frames BEFORE expensive fountain decoding.
    NOT for long-term message authentication (manifest HMAC handles that).

SECURITY ANALYSIS:
    • Birthday bound: ~2^32 frames needed to find any collision
    • Practical frame count: <10,000 frames per GIF (typical: 100-1000)
```

**Status**: ✅ NO ACTION NEEDED (already documented)

---

### CRIT-03: Python Backend Dead Code Removal

**Finding**: Python crypto backend code present but unreachable (Rust required).
Dead code increases attack surface and maintenance burden.

**Resolution**: Removed ~200 lines of `PythonCryptoBackend` class from
`meow_decoder/crypto_backend.py`. Added comment at removal point:
```python
# PythonCryptoBackend has been removed to eliminate dead code risk.
# Rust backend (meow_crypto_rs) is now REQUIRED for all operations.
```

**Files Modified**:
- `meow_decoder/crypto_backend.py`: Removed lines 175-567

**Verification**:
```bash
grep -n "PythonCryptoBackend" meow_decoder/crypto_backend.py
# Should only show removal comment, not class definition
```

**Status**: ✅ RESOLVED

---

### CRIT-04: Duress Password Timing Oracle Fix

**Finding**: Duress password check used fast SHA-256 hash before Argon2id derivation,
creating potential timing oracle to distinguish duress from real password attempts.

**Resolution**: Restructured `decode_gif.py` to **always run Argon2id first**:
```python
# SECURITY (CRIT-04): Always run Argon2id BEFORE duress/HMAC checks to prevent timing oracle.
# An attacker measuring timing could distinguish duress (fast SHA-256) from real (slow Argon2id).
# By running Argon2id first, both paths have identical timing characteristics.
# See CRYPTO_SECURITY_REVIEW.md § CRIT-04 for full rationale.
```

**Code Flow (After Fix)**:
1. Run Argon2id key derivation (slow, ~5-10 seconds)
2. Check duress tag with derived key
3. Verify manifest HMAC

**Files Modified**:
- `meow_decoder/decode_gif.py`: Lines 169-188

**Verification**:
```bash
grep -A5 "CRIT-04" meow_decoder/decode_gif.py
```

**Status**: ✅ RESOLVED

---

### CRIT-05: liboqs-python Status

**Finding**: `liboqs-python` commented out in requirements.txt.

**Resolution**: Intentional - liboqs-python is optional and only needed for
post-quantum operations. The Rust backend provides PQ crypto when the `pq-crypto`
feature is enabled. This is documented in requirements.txt:
```
# Optional: Post-quantum crypto (requires compilation from source)
# liboqs-python>=0.9.0
```

**Status**: ✅ BY DESIGN (optional dependency)

---

## Phase 2: Verification & Testing ✅ COMPLETED

All Phase 2 security tests have been implemented in `tests/test_phase2_security.py`:

| ID | Task | Priority | Status |
|----|------|----------|--------|
| P2-01 | Timing oracle unit tests for duress path | HIGH | ✅ Implemented |
| P2-02 | Nonce uniqueness assertion tests | MEDIUM | ✅ Implemented |
| P2-03 | Frame MAC birthday bound adversarial test | LOW | ✅ Implemented |
| P2-04 | Document key compromise impersonation model | LOW | Deferred (formal verification) |

### New Test Classes Added

**TestNonceUniqueness** (P2-02):
- `test_same_key_nonce_raises_on_reuse` - Verifies nonce reuse is detected
- `test_different_nonces_allowed` - Different nonces work correctly
- `test_different_keys_same_nonce_allowed` - Different key contexts work
- `test_cache_eviction_does_not_cause_false_positive` - Documents cache behavior

**TestTimingOracleResistance** (P2-01):
- `test_constant_time_compare_uses_secrets_module` - Verifies proper primitive usage
- `test_hmac_verification_timing_consistency` - Statistical timing analysis
- `test_frame_mac_verification_no_early_exit` - No early exit on mismatch

**TestFrameMACBirthdayBound** (P2-03 / GAP-07):
- `test_mac_uniqueness_within_session` - 1000 MACs all unique
- `test_mac_uniqueness_across_sessions` - Cross-session uniqueness
- `test_per_frame_key_derivation_uniqueness` - Key derivation uniqueness
- `test_birthday_bound_adversarial` - 4096 random MAC collision test
- `test_mac_size_is_documented` - Verify 8-byte MAC size

**TestDuressTimingProtection**:
- `test_duress_check_imports_exist` - API availability
- `test_duress_tag_uses_constant_time_compare` - Constant-time verification

**TestKeyDerivationSecurity**:
- `test_different_salts_produce_different_keys` - Salt uniqueness
- `test_key_derivation_deterministic` - Determinism verification
- `test_minimum_password_length_enforced` - Password policy enforcement

---

## Security Invariants Preserved

All changes maintain these security invariants:

1. **Auth-Then-Output**: No plaintext output without HMAC+AEAD verification
2. **Constant-Time Comparisons**: All MAC/password comparisons use `secrets.compare_digest()`
3. **Memory Zeroization**: Sensitive data zeroed via Rust `zeroize` crate
4. **Nonce Uniqueness**: Per-process cache + random generation
5. **Domain Separation**: HKDF info strings separate all derived keys

---

## Testing Verification

Run all security tests:
```bash
MEOW_TEST_MODE=1 pytest tests/test_security.py tests/test_frame_mac.py tests/test_phase2_security.py -v
```

Phase 2 tests specifically:
```bash
MEOW_TEST_MODE=1 pytest tests/test_phase2_security.py -v
```

---

## Phase 3: Schrödinger Mode Timing Security ✅ COMPLETED

Phase 3 addresses timing oracle vulnerabilities in Schrödinger mode (dual-reality
plausible deniability) and adds comprehensive adversarial testing.

### P3-01 & P3-02: Schrödinger Timing Oracle Fix

**Finding**: The Schrödinger decoder tried Reality A first, then Reality B, creating
a timing oracle that could reveal which reality was accessed:
- Reality A match: 1× Argon2id (~5 seconds)
- Reality B match: 2× Argon2id (~10 seconds)
- Neither match: 2× Argon2id (~10 seconds)

This timing difference could allow an adversary to determine which password was used,
defeating the plausible deniability guarantees.

**Resolution**: Complete rewrite of `schrodinger_decode_data()` to be timing-safe:

```python
# SECURITY (TIMING-01): Derive BOTH keys upfront - no early exit
master_meta_key_a = derive_key(password, manifest.salt_a)
master_meta_key_b = derive_key(password, manifest.salt_b)

# Derive BOTH HMAC keys
hmac_key_a = HKDF(...).derive(master_meta_key_a)
hmac_key_b = HKDF(...).derive(master_meta_key_b)

# SECURITY (TIMING-02): Check BOTH HMACs (constant-time)
expected_hmac_a = hmac.new(hmac_key_a, manifest_core, hashlib.sha256).digest()
expected_hmac_b = hmac.new(hmac_key_b, manifest_core, hashlib.sha256).digest()
is_reality_a = secrets.compare_digest(expected_hmac_a, manifest.reality_a_hmac)
is_reality_b = secrets.compare_digest(expected_hmac_b, manifest.reality_b_hmac)

# Add random delay to mask any residual timing differences (1-10ms)
time.sleep(secrets.randbelow(10) / 1000.0)

# NOW branch based on which reality matched
if is_reality_a:
    # ... decrypt Reality A
elif is_reality_b:
    # ... decrypt Reality B
else:
    return None  # Neither matched
```

**Trade-off**: Decryption now takes 2× the time (both Argon2id derivations always run),
but timing is constant regardless of which password was used.

**Files Modified**:
- `meow_decoder/schrodinger_decode.py`: Complete rewrite of `schrodinger_decode_data()`

**Verification**:
```bash
grep -A10 "TIMING-01\|TIMING-02" meow_decoder/schrodinger_decode.py
```

**Status**: ✅ RESOLVED

---

### P3-03 & P3-04: Schrödinger Adversarial Test Suite

**Finding** (GAP-04): Schrödinger mode adversarial testing was limited.

**Resolution**: Created comprehensive test suite in `tests/test_phase3_schrodinger_security.py`:

**TestSchrodingerTimingResistance**:
- `test_both_argon2id_derivations_run` - Verifies decode works after timing fix
- `test_wrong_password_timing_consistent` - Statistical timing analysis
- `test_reality_a_vs_b_timing_similar` - No timing difference between realities

**TestSchrodingerAdversarial**:
- `test_cross_reality_hmac_substitution` - Swap HMACs → detected
- `test_salt_substitution_attack` - Swap salts → detected
- `test_metadata_tampering_detected` - Bit flip in metadata → detected
- `test_superposition_corruption_handling` - Graceful corruption handling
- `test_manifest_version_binding` - Version bound to HMAC

**TestQuantumMixerSecurity**:
- `test_statistical_indistinguishability` - Both halves have similar entropy
- `test_collapse_correctness` - Correct data extraction
- `test_different_length_realities` - Padding handled correctly

**TestSchrodingerRoundtrip**:
- `test_basic_roundtrip_both_realities` - Full encode/decode cycle
- `test_password_independence` - One password reveals nothing about other reality

**Files Created**:
- `tests/test_phase3_schrodinger_security.py` (~350 lines)

**Verification**:
```bash
MEOW_TEST_MODE=1 pytest tests/test_phase3_schrodinger_security.py -v
```

**Status**: ✅ RESOLVED

---

## Security Invariants Preserved

All changes maintain these security invariants:

1. **Auth-Then-Output**: No plaintext output without HMAC+AEAD verification
2. **Constant-Time Comparisons**: All MAC/password comparisons use `secrets.compare_digest()`
3. **Memory Zeroization**: Sensitive data zeroed via Rust `zeroize` crate
4. **Nonce Uniqueness**: Per-process cache + random generation
5. **Domain Separation**: HKDF info strings separate all derived keys
6. **Timing-Safe Schrödinger**: Both realities always processed identically

---

## Testing Verification

Run all security tests:
```bash
MEOW_TEST_MODE=1 pytest tests/test_security.py tests/test_frame_mac.py \
    tests/test_phase2_security.py tests/test_phase3_schrodinger_security.py -v
```

Phase 3 tests specifically:
```bash
MEOW_TEST_MODE=1 pytest tests/test_phase3_schrodinger_security.py -v
```

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-28 | Initial Phase 1 completion |
| 1.1 | 2026-01-29 | Phase 2 test implementation complete |
| 1.2 | 2026-01-29 | Phase 3 Schrödinger timing security complete |

---

**Reviewed by**: Security Review Process  
**Next Review**: Formal verification (Tamarin/ProVerif models)

