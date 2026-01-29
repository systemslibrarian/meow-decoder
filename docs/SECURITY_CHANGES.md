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

## Phase 2: Verification & Testing (Planned)

The following improvements are recommended for Phase 2:

| ID | Task | Priority |
|----|------|----------|
| P2-01 | Add timing oracle unit tests for duress path | HIGH |
| P2-02 | Add nonce uniqueness assertion tests | MEDIUM |
| P2-03 | Add frame MAC birthday bound adversarial test | LOW |
| P2-04 | Document key compromise impersonation model | LOW |

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

All existing security tests pass after these changes:
```bash
pytest tests/test_security.py tests/test_frame_mac.py tests/test_adversarial.py -v
```

New tests added:
- None (documentation-only changes for CRIT-02)

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-28 | Initial Phase 1 completion |

---

**Reviewed by**: Security Review Process  
**Next Review**: Phase 2 completion
