# 🔒 Security Invariants - Meow Decoder

**Version:** 6.0  
**Last Updated:** 2026-01-25  
**Classification:** Security-Critical Documentation

---

## Overview

This document formally specifies the **security invariants** that Meow Decoder MUST uphold. These are mathematical properties that must hold for ALL inputs - violating any invariant is a security vulnerability.

Invariants are verified through:
1. **Property-based testing** (Hypothesis) - Random input fuzzing
2. **Unit tests** - Specific edge cases
3. **Fuzzing** (AFL++) - Crash detection
4. **Code review** - Manual verification

---

## Critical Invariants

### INV-001: Encrypt-Decrypt Roundtrip

```
∀ plaintext, password, keyfile:
    decrypt(encrypt(plaintext, password, keyfile), password, keyfile) == plaintext
```

**Description:** Decryption must exactly recover the original plaintext for any valid inputs.

**Verification:**
- `tests/test_property_based.py::TestEncryptDecryptInvariants::test_aes_gcm_roundtrip_*`
- `tests/test_property_based.py::TestEncryptDecryptInvariants::test_file_encrypt_decrypt_roundtrip`
- `tests/test_e2e.py::test_encode_decode_roundtrip`

**Failure Impact:** Data corruption, unrecoverable files.

---

### INV-002: Authentication Before Decryption

```
∀ ciphertext, key, nonce, aad:
    IF tampered(ciphertext) OR tampered(aad) THEN
        decrypt(ciphertext, key, nonce, aad) RAISES Exception
```

**Description:** AES-GCM MUST verify the authentication tag BEFORE releasing any plaintext. This prevents chosen-ciphertext attacks.

**Implementation:**
- AES-GCM authentication tag (16 bytes)
- Manifest HMAC-SHA256 (32 bytes)
- Per-frame MAC (8 bytes)

**Verification:**
- `tests/test_property_based.py::TestTamperDetection::test_ciphertext_tampering_detected`
- `tests/test_property_based.py::TestTamperDetection::test_aad_tampering_detected`
- `tests/test_security.py::TestTamperDetection`

**Failure Impact:** Forgery attacks, accepting malicious data.

---

### INV-003: Nonce Uniqueness

```
∀ encryptions e1, e2 with same key K:
    IF e1 ≠ e2 THEN nonce(e1) ≠ nonce(e2)
```

**Description:** Nonce reuse with the same key completely breaks AES-GCM security. Each encryption MUST use a unique (salt, nonce) pair.

**Implementation:**
- 96-bit random nonce from `secrets.token_bytes(12)`
- 128-bit random salt for key derivation
- Combined (salt, nonce) is effectively 224 bits of randomness
- Per-process nonce cache to detect accidental reuse

**Verification:**
- `tests/test_property_based.py::TestNonceUniqueness::test_nonces_never_repeat`
- `tests/test_security.py::test_nonce_uniqueness`

**Failure Impact:** Complete cipher break, XOR of plaintexts revealed.

---

### INV-004: AAD Binding (Manifest Integrity)

```
∀ manifest M, ciphertext C encrypted with key K:
    M is bound to C via AES-GCM AAD
    Changing any field in M invalidates decryption
```

**Description:** The manifest (containing lengths, hashes, parameters) MUST be cryptographically bound to the ciphertext. This prevents substitution attacks.

**AAD Contents:**
```python
aad = struct.pack('<QQ', orig_len, comp_len)  # Lengths
aad += salt                                     # Salt
aad += sha256                                   # Original hash
aad += MAGIC                                    # Version
if ephemeral_public_key:
    aad += ephemeral_public_key                 # FS key binding
```

**Verification:**
- `tests/test_invariants.py::TestSecurityInvariants::test_invariant_aad_modification_rejected`
- `tests/test_security.py::TestTamperDetection::test_manifest_tampering`

**Failure Impact:** Length oracle attacks, version downgrade attacks.

---

### INV-005: Backend Parity

```
∀ inputs I, operation O:
    Python_Backend.O(I) == Rust_Backend.O(I)
```

**Description:** The Rust and Python backends MUST produce byte-for-byte identical outputs for the same inputs. This ensures interoperability and allows seamless fallback.

**Covered Operations:**
- `aes_gcm_encrypt` / `aes_gcm_decrypt`
- `derive_key_argon2id`
- `derive_key_hkdf`
- `hmac_sha256` / `hmac_sha256_verify`
- `sha256`
- `x25519_generate_keypair` / `x25519_exchange`

**Verification:**
- `tests/test_property_based.py::TestBackendParity::*`
- `tests/test_backend_parity.py`

**Failure Impact:** Cross-platform incompatibility, decryption failures.

---

### INV-006: Key Derivation Determinism

```
∀ password P, salt S, keyfile K:
    derive_key(P, S, K) == derive_key(P, S, K)  // Same inputs → same output
    
∀ P1 ≠ P2, S:
    derive_key(P1, S) ≠ derive_key(P2, S)       // Different passwords → different keys

∀ P, S1 ≠ S2:
    derive_key(P, S1) ≠ derive_key(P, S2)       // Different salts → different keys
```

**Description:** Key derivation must be deterministic (for decryption to work) but also ensure different inputs produce different keys.

**Verification:**
- `tests/test_property_based.py::TestKeyDerivationInvariants::*`

**Failure Impact:** Decryption failure, key collision attacks.

---

### INV-007: Constant-Time Comparison

```
∀ a, b with len(a) == len(b):
    time(compare(a, b)) is independent of (a, b)
```

**Description:** All security-critical comparisons MUST execute in constant time to prevent timing attacks.

**Implementation:**
- `secrets.compare_digest()` for password/MAC comparison
- Rust `subtle` crate for constant-time ops
- Timing equalization delays (1-5ms jitter)

**Verification:**
- `tests/test_property_based.py::TestConstantTimeInvariants::*`
- `tests/test_constant_time.py`

**Failure Impact:** Timing attacks can leak password/key bits.

---

### INV-008: Manifest Serialization Lossless

```
∀ manifest M:
    unpack_manifest(pack_manifest(M)) == M
```

**Description:** Manifest serialization must be perfectly reversible with no data loss.

**Verification:**
- `tests/test_property_based.py::TestManifestInvariants::test_manifest_roundtrip`

**Failure Impact:** Data corruption, decryption parameter loss.

---

### INV-009: Fountain Code Recoverability

```
∀ data D, with k_blocks K:
    IF received >= ceil(K * 1.05) droplets THEN
        decode_probability > 0.99
```

**Description:** Fountain codes (Luby Transform) must allow recovery with approximately k blocks (with small overhead).

**Verification:**
- `tests/test_property_based.py::TestFountainCodeInvariants::test_fountain_roundtrip`
- `tests/test_fountain.py`

**Failure Impact:** Unrecoverable data despite sufficient frames.

---

### INV-010: X25519 Commutativity

```
∀ keypairs (a, A) and (b, B):
    ECDH(a, B) == ECDH(b, A)
```

**Description:** X25519 key exchange must be commutative - both parties derive the same shared secret.

**Verification:**
- `tests/test_property_based.py::TestX25519Invariants::test_x25519_shared_secret_commutative`

**Failure Impact:** Forward secrecy broken, key mismatch.

---

### INV-011: HMAC Tamper Detection

```
∀ key K, message M, tag T = HMAC(K, M):
    ∀ M' ≠ M: HMAC_verify(K, M', T) == False
```

**Description:** HMAC verification must reject any modification to the authenticated message.

**Verification:**
- `tests/test_property_based.py::TestTamperDetection::test_hmac_tampering_detected`

**Failure Impact:** Message forgery, manifest tampering.

---

### INV-012: Wrong Password Rejection

```
∀ ciphertext C encrypted with password P:
    ∀ P' ≠ P: decrypt(C, P') RAISES Exception
```

**Description:** Decryption with an incorrect password MUST fail cleanly (not produce garbage).

**Implementation:**
- HMAC verification before decryption
- AES-GCM tag verification
- SHA-256 hash verification of decrypted data

**Verification:**
- `tests/test_e2e.py::test_wrong_password`
- `tests/test_invariants.py::test_invariant_wrong_password_rejected`

**Failure Impact:** Silent data corruption, oracle attacks.

---

### INV-013: Secure Memory Zeroing

```
∀ sensitive data S (passwords, keys):
    AFTER use: S is overwritten with zeros
```

**Description:** Sensitive data must be securely zeroed after use to prevent memory forensics.

**Implementation:**
- `SecureBytes` class with `__del__` zeroing
- Rust `zeroize` crate for automatic zeroing
- `mlock()` to prevent swap (where available)

**Verification:**
- `tests/test_constant_time.py::test_secure_memory_zeroing`

**Failure Impact:** Key recovery via memory forensics.

---

### INV-014: Duress Detection Timing

```
∀ passwords P (normal), D (duress):
    time(check(P)) ≈ time(check(D))
```

**Description:** Checking for a duress password must not reveal whether the password was the duress password through timing.

**Implementation:**
- Constant-time comparison with `secrets.compare_digest()`
- Timing equalization with random delays

**Verification:**
- `tests/test_duress_mode.py::test_duress_timing`

**Failure Impact:** Attacker can distinguish duress from real password.

---

### INV-015: Frame MAC Authentication

```
∀ frame F with MAC M computed with key K, salt S, index I:
    IF modified(F) OR modified(M) THEN
        verify_frame_mac(F, M, K, S, I) == False
```

**Description:** Per-frame MACs prevent injection of malicious frames into the QR stream.

**Verification:**
- `tests/test_frame_mac.py`
- `tests/test_adversarial.py::test_frame_injection`

**Failure Impact:** DoS via malicious frame injection.

---

## Invariant Test Matrix

| Invariant | Property Tests | Unit Tests | Fuzzing | Status |
|-----------|---------------|------------|---------|--------|
| INV-001 | ✅ | ✅ | ✅ | VERIFIED |
| INV-002 | ✅ | ✅ | ✅ | VERIFIED |
| INV-003 | ✅ | ✅ | - | VERIFIED |
| INV-004 | ✅ | ✅ | ✅ | VERIFIED |
| INV-005 | ✅ | ✅ | - | VERIFIED |
| INV-006 | ✅ | ✅ | - | VERIFIED |
| INV-007 | ✅ | ✅ | - | PARTIAL* |
| INV-008 | ✅ | ✅ | ✅ | VERIFIED |
| INV-009 | ✅ | ✅ | ✅ | VERIFIED |
| INV-010 | ✅ | ✅ | - | VERIFIED |
| INV-011 | ✅ | ✅ | - | VERIFIED |
| INV-012 | ✅ | ✅ | - | VERIFIED |
| INV-013 | - | ✅ | - | PARTIAL* |
| INV-014 | - | ✅ | - | PARTIAL* |
| INV-015 | - | ✅ | - | VERIFIED |

*PARTIAL indicates implementation is best-effort due to Python limitations.

---

## Adding New Invariants

When adding a new security-critical feature:

1. **Document the invariant** in this file
2. **Add property-based tests** in `tests/test_property_based.py`
3. **Add targeted unit tests** in appropriate test file
4. **Add fuzz target** in `fuzz/` if parsing is involved
5. **Update the test matrix** above

---

## Verification Commands

```bash
# Run all property-based tests
pytest tests/test_property_based.py -v --hypothesis-show-statistics

# Run invariant tests only
pytest tests/test_invariants.py -v

# Run full security test suite
pytest tests/test_security.py tests/test_invariants.py tests/test_property_based.py -v

# Run with coverage for crypto paths
pytest --cov=meow_decoder.crypto --cov=meow_decoder.crypto_backend \
    --cov-report=html --cov-fail-under=90

# Run fuzzing
python -m atheris fuzz/fuzz_manifest.py
```

---

## References

- [AES-GCM Nonce Reuse Attack](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Argon2 OWASP Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Timing Attacks on Web Applications](https://www.usenix.org/conference/usenixsecurity11/timing-attacks-web-applications)
- [NIST SP 800-63B Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

**Security Contact:** Open a GitHub issue with [SECURITY] tag
