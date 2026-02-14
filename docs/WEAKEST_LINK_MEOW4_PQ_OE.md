# MEOW4 PQ Duress Observational Equivalence — Weakest-Link Analysis

**Model:** `formal/tamarin/MeowDuressEquivPQ.spthy`  
**Property:** Real-password sessions are observationally equivalent to duress-password sessions under MEOW4 hybrid KEM (X25519 + ML-KEM-1024 + password-based encryption).  
**Date:** February 2026

---

## Executive Summary

The MEOW4 duress observational equivalence proof in Tamarin **symbolically proves** that an adversary observing:
- Encrypted GIF frames (optical air-gap channel)
- KEM ciphertext (ML-KEM-1024, 1568 bytes)
- X25519 ephemeral public key (32 bytes)
- Authentication failure messages (identical for all reject paths)

**CANNOT** distinguish real-password decoding from duress-password decoding.

### Weakest-Link Assumption

The **single strongest assumption** this proof relies on is:

> **IND-CCA2 security of ML-KEM-1024 (NIST FIPS 203 standard)**

If this KEM is broken (i.e., an attacker can distinguish encapsulations of distinct shared secrets), the observational equivalence proof **may no longer hold** because:
1. The attacker could use KEM distinguishing to infer properties of the derived key
2. Key derivation depends on the KEM shared secret via `hybrid_ss = HKDF(x25519_ss || kem_ss)`
3. Breaking IND-CCA2 could leak information about which password was used

All other assumptions (X25519 DDH, HMAC-SHA256 PRF, AES-GCM AEAD, Argon2id KDF) are **auxiliary** — if any single one breaks, the scheme may still resist CRQC attackers due to hybrid construction.

---

## Cryptographic Assumptions (Ordered by Strength)

### 1. **ML-KEM-1024 IND-CCA2 Security** ⚠️ **WEAKEST LINK**

- **What:** ML-KEM-1024 (Kyber1024) is IND-CCA2 secure against Chosen-Ciphertext Attacks
- **Implication:** Attacker cannot distinguish `kem_encap(pk, coins_real)` from `kem_encap(pk, coins_duress)` or learn `kem_ss` from `kem_ct`
- **Standard:** NIST FIPS 203 (2024), CRYSTALS-Kyber finalist
- **Security Level:** NIST Level 5 (256-bit post-quantum security)
- **Rationale:** This is the **only** post-quantum component. If broken by CRQC, hybrid construction falls back to X25519+password, which may also be CRQC-vulnerable.

**Failure Mode:** If ML-KEM-1024 is fully broken (quantum algorithm finds `kem_ss`), attacker may still need to:
- Break X25519 (Shor's algorithm — feasible for CRQC)
- Guess password (still ≥2^128 entropy if strong passphrase)
- Recover from combined HKDF output (still PRF-secure against known-plaintext)

### 2. **X25519 Diffie-Hellman (DDH) Hardness**

- **What:** Decisional Diffie-Hellman problem is hard on Curve25519
- **Implication:** Attacker cannot distinguish `g^(ab)` from random given `g^a, g^b`
- **Standard:** RFC 7748 (2016), IETF recommended
- **Security Level:** 128-bit classical, **0-bit post-quantum** (Shor's algorithm breaks this)
- **Hybrid Mitigation:** Combined with ML-KEM via `HKDF(x25519_ss || kem_ss)` — attacker must break **both** to recover `hybrid_ss`

**Failure Mode:** If X25519 is broken (CRQC with Shor), attacker still needs to break ML-KEM-1024 or password.

### 3. **Argon2id KDF Security**

- **What:** Password-derived keys are indistinguishable from random (PRF security)
- **Implication:** `kdf(pw_real, salt, argon2)` is computationally indistinguishable from `kdf(pw_duress, salt, argon2)` without knowing passwords
- **Standard:** RFC 9106 (2021), IETF-recommended password hashing
- **Parameters:** 512 MiB memory, 20 iterations, 4 threads (production mode)
- **Security Level:** ~2^128 brute-force cost (assuming ≥128-bit password entropy)

**Failure Mode:** Weak passwords (e.g., "password123") allow offline brute-force even if KEM/DH are secure.

### 4. **HMAC-SHA256 PRF Security**

- **What:** HMAC-SHA256 is a secure PRF (indistinguishable from random function)
- **Implication:** `hmac(key, <ciphertext, kem_ct, eph_pk>)` leaks no information about `key`
- **Standard:** FIPS 198-1 (2008), NIST-approved
- **Security Level:** 128-bit PRF security (SHA-256 has 256-bit output, PRF security ≥min(key_len, 128))

**Failure Mode:** If HMAC-SHA256 is broken (e.g., PRF distinguisher found), attacker may learn key material from manifest. This would also break AES-GCM AAD binding.

### 5. **AES-256-GCM AEAD Security**

- **What:** AES-GCM provides IND-CCA3 authenticated encryption
- **Implication:** Ciphertexts leak no information about plaintexts, tampering is detected
- **Standard:** NIST SP 800-38D (2007)
- **Security Level:** 256-bit key, 128-bit authentication tag

**Failure Mode:** If AES-256 is broken (quantum Grover reduces to 128-bit security), ciphertext confidentiality may be compromised. Authentication still relies on GCM tag.

### 6. **HKDF-SHA256 KDF Security**

- **What:** HKDF is a secure key derivation function (extract-then-expand)
- **Implication:** `HKDF(x25519_ss || kem_ss, "meow_hybrid_pq_v1")` is indistinguishable from random
- **Standard:** RFC 5869 (2010)
- **Security Level:** PRF security of SHA-256 (128-bit)

**Failure Mode:** If HKDF is broken, attacker may learn one component (e.g., `x25519_ss`) from `hybrid_ss`.

---

## Symbolic Model Limitations

Tamarin uses a **Dolev-Yao symbolic attacker** with perfect cryptography assumptions. The following are **NOT** proven:

### 1. **Side-Channel Resistance**

- Timing attacks on Argon2id, HMAC, AES-GCM
- Cache-timing on KEM decapsulation
- Power analysis on embedded devices

**Mitigation:** Python implementation uses `constant_time.py::equalize_timing()` (NOT formally verified).

### 2. **Implementation Correctness**

- Python cryptography library bugs
- liboqs (ML-KEM) implementation bugs
- Memory safety (overflow, UAF, etc.)

**Mitigation:** Test suite in `tests/test_security.py` (black-box, not white-box verification).

### 3. **Random Number Generator Security**

- Tamarin assumes perfect randomness (`Fr(~coins)`)
- Real implementation uses `os.urandom()` (kernel CSPRNG)

**Failure Mode:** Weak RNG allows attacker to predict ephemeral keys or KEM coins.

### 4. **Human Factors**

- Users choosing weak passwords
- Users revealing passwords under coercion
- Decoy data not plausible (social engineering)

**Out of Scope:** This is a protocol-level proof, not a system-level proof.

### 5. **Optical Channel Attacks**

- High-speed camera detecting QR code generation timing
- Fountain code droplet correlation attacks
- Frame count analysis (number of frames = metadata leak)

**Partial Mitigation:** Fountain codes provide rateless encoding (frame count depends on channel quality, not plaintext size). GIF timing equalization masks some variance.

---

## Attack Scenarios & Residual Security

### Scenario 1: CRQC (Cryptographically-Relevant Quantum Computer)

**Attacker Capability:**
- Breaks X25519 via Shor's algorithm (polynomial time)
- Cannot break ML-KEM-1024 (no known quantum algorithm)

**Residual Security:**
- Duress OE **HOLDS** — attacker still needs to:
  1. Break ML-KEM-1024 (assumed hard)
  2. OR brute-force password (2^128 cost if strong)

**Conclusion:** Hybrid construction provides defense-in-depth.

### Scenario 2: ML-KEM-1024 Broken (Cryptanalytic Breakthrough)

**Attacker Capability:**
- Solves MLWE (Module Learning With Errors) efficiently
- Can recover `kem_ss` from `kem_ct`

**Residual Security:**
- Falls back to X25519 + password-based encryption (MEOW3 mode)
- If X25519 also broken, security relies solely on password entropy

**Conclusion:** Scheme degrades gracefully to classical+password security.

### Scenario 3: Both KEM Components Broken

**Attacker Capability:**
- Breaks X25519 (quantum)
- Breaks ML-KEM-1024 (cryptanalytic)

**Residual Security:**
- Security depends **entirely** on password entropy
- Attacker must brute-force Argon2id (2^128 cost for strong password)
- Duress OE **MAY FAIL** if attacker can distinguish `kdf(pw_real)` from `kdf(pw_duress)` via side-channel

**Conclusion:** This is the **worst-case scenario** — password is the last defense.

### Scenario 4: Weak Password (e.g., "password123")

**Attacker Capability:**
- Online or offline password guessing
- Dictionary attack against Argon2id

**Residual Security:**
- **NONE** — attacker recovers both real and duress keys
- Duress OE **FAILS** — attacker can test both passwords and see which decrypts successfully

**Conclusion:** Strong passwords (≥128-bit entropy) are **required**.

---

## Proof Coverage vs. Real-World Deployment

| Property | Tamarin Model | Python Implementation | Gap |
|----------|---------------|----------------------|-----|
| **Symbolic OE** | ✅ Proved | ✅ Implemented | Computational OE not proved |
| **IND-CCA2 KEM** | ✅ Assumed | ✅ liboqs FIPS 203 | Side-channels not verified |
| **Timing Equalization** | ❌ Out of scope | ✅ `equalize_timing()` | NOT formally verified |
| **Memory Safety** | ❌ Out of scope | ⚠️ Python (memory-safe language) | C dependencies (liboqs) not verified |
| **RNG Quality** | ✅ Assumed perfect | ✅ `os.urandom()` | Kernel RNG bugs possible |
| **Denial of Service** | ❌ Out of scope | ❌ Not hardened | Attacker can exhaust memory/CPU |
| **Decoy Plausibility** | ❌ Out of scope | ⚠️ User responsibility | No automated quality check |

---

## Recommended Mitigations

### For Users

1. **Use strong passwords:** ≥128-bit entropy (e.g., 7+ Diceware words)
2. **Prepare plausible decoys:** Decoy data must withstand social engineering
3. **Avoid password reuse:** Real and duress passwords must be independent
4. **Use air-gapped devices:** Prevent network-based attacks during decode

### For Developers

1. **Add side-channel hardening:** Constant-time implementations for all cryptographic operations
2. **Fuzz-test fountain decoder:** Ensure malformed droplets don't crash decoder
3. **Rate-limit password attempts:** Prevent online brute-force attacks
4. **Add ML-KEM agility:** Support fallback to ML-KEM-768/1024 or future NIST standards

### For Auditors

1. **Verify liboqs correctness:** Check ML-KEM-1024 implementation against NIST test vectors
2. **Audit constant-time code:** Ensure `equalize_timing()` actually masks timing variance
3. **Review Argon2id parameters:** 512 MiB / 20 iterations may be too slow for mobile devices

---

## References

- **NIST FIPS 203** (2024): Module-Lattice-Based Key-Encapsulation Mechanism Standard
- **Bellare, Canetti, Krawczyk** (1998): "A modular approach to the design and analysis of authentication and key exchange protocols." STOC 1998.
- **Barak et al.** (2006): "On the (im)possibility of obfuscating programs." JACM.
- **Canetti, Krawczyk** (2001): "Analysis of Key-Exchange Protocols and Their Use for Building Secure Channels." EUROCRYPT 2001.
- **Giacon, Heuer, Poettering** (2018): "KEM Combiners." PKC 2018.

---

## Conclusion

The MEOW4 duress observational equivalence proof provides **strong symbolic assurance** that the protocol hides which password was used, assuming:
1. **ML-KEM-1024 is IND-CCA2 secure** (weakest link)
2. X25519, HMAC, AES-GCM, Argon2id are secure (standard assumptions)
3. Implementation is correct (partial test coverage)
4. Users choose strong passwords (≥128-bit entropy)

**The proof does NOT cover:**
- Side-channel attacks (timing, cache, power)
- Implementation bugs (memory safety, RNG failures)
- Human factors (weak passwords, implausible decoys)

**For a production audit, we recommend:**
- Computational security proofs (game-based, not symbolic)
- Side-channel analysis (timing measurements, cache profiling)
- Fuzz testing (AFL++, libFuzzer on decoder)
- User studies (decoy plausibility evaluation)
