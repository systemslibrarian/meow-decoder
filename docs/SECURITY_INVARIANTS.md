# 🔒 Security Invariants - Meow Decoder

**Version:** 5.8.0  
**Date:** 2026-01-25  
**Status:** Verification Targets

---

## Overview

This document defines the **security invariants** that Meow Decoder must maintain. These are properties that must ALWAYS be true for the system to be considered secure.

Future formal verification efforts should prove these invariants mathematically.

---

## Cryptographic Invariants

### INV-1: Key Derivation Determinism

```
∀ password, salt, params:
  derive_key(password, salt, params) = derive_key(password, salt, params)
```

**Property:** Same inputs MUST produce identical keys.  
**Verification:** Property-based testing with Hypothesis.  
**Module:** `crypto.py`, `crypto_backend.py`

### INV-2: Encryption Uniqueness

```
∀ key, plaintext:
  encrypt(key, plaintext) ≠ encrypt(key, plaintext)
  (due to random nonce)
```

**Property:** Same plaintext encrypted twice MUST produce different ciphertext.  
**Reason:** Nonce reuse would break AES-GCM security.  
**Module:** `crypto.py`

### INV-3: Decryption Correctness

```
∀ key, plaintext, nonce, aad:
  decrypt(key, nonce, encrypt(key, nonce, plaintext, aad), aad) = plaintext
```

**Property:** Decryption MUST recover original plaintext.  
**Module:** `crypto.py`, `crypto_backend.py`

### INV-4: Authentication Binding

```
∀ key, nonce, ciphertext, aad, aad':
  aad ≠ aad' → decrypt(key, nonce, ciphertext, aad') = ⊥ (error)
```

**Property:** Modifying AAD MUST cause decryption to fail.  
**Reason:** AAD binds metadata to ciphertext.  
**Module:** `crypto.py`

### INV-5: HMAC Integrity

```
∀ key, data:
  verify_hmac(key, data, hmac(key, data)) = true
  
∀ key, data, tag' where tag' ≠ hmac(key, data):
  verify_hmac(key, data, tag') = false
```

**Property:** Valid HMAC MUST verify; invalid MUST reject.  
**Module:** `crypto.py`, `constant_time.py`

### INV-6: Constant-Time Comparison

```
∀ a, b, |a| = |b|:
  time(compare(a, b)) ≈ constant
  (independent of position of first difference)
```

**Property:** Comparison time MUST NOT leak information about where values differ.  
**Module:** `constant_time.py`, Rust `subtle` crate

---

## Forward Secrecy Invariants

### INV-7: Ephemeral Key Independence

```
∀ encryption_session:
  ephemeral_private_key is generated fresh
  ephemeral_private_key is destroyed after key exchange
```

**Property:** Each encryption uses independent ephemeral keys.  
**Module:** `x25519_forward_secrecy.py`

### INV-8: Key Compromise Non-Retroactivity

```
∀ past_ciphertext, compromised_long_term_key:
  decrypt(compromised_long_term_key, past_ciphertext) = ⊥
```

**Property:** Compromising the long-term key MUST NOT decrypt past messages.  
**Module:** `forward_secrecy.py`, `x25519_forward_secrecy.py`

### INV-9: Double Ratchet Progression

```
∀ ratchet_state:
  ratchet_step(state) → state'
  derive_key(state) ≠ derive_key(state')
```

**Property:** Each ratchet step produces a new independent key.  
**Module:** `double_ratchet.py`

---

## Plausible Deniability Invariants (Schrödinger Mode)

### INV-10: Statistical Indistinguishability

```
∀ reality_a, reality_b, superposition:
  entropy(extract_a(superposition)) ≈ entropy(extract_b(superposition))
  chi_square(superposition) passes randomness tests
```

**Property:** Neither reality can be statistically distinguished.  
**Module:** `quantum_mixer.py`, `schrodinger_encode.py`

### INV-11: Independent Decryptability

```
∀ password_a, password_b, superposition:
  decrypt(password_a, superposition) = reality_a
  decrypt(password_b, superposition) = reality_b
  (neither reveals the other)
```

**Property:** Each password independently decrypts its reality.  
**Module:** `schrodinger_decode.py`

### INV-12: Quantum Noise Binding

```
∀ password_a, password_b:
  quantum_noise = f(hash(password_a) ⊕ hash(password_b))
  (requires both passwords to derive)
```

**Property:** Quantum noise cryptographically binds both realities.  
**Module:** `quantum_mixer.py`

---

## Memory Safety Invariants

### INV-13: Key Zeroing

```
∀ key in memory:
  after use: memory_content(key_location) = 0x00...
```

**Property:** Keys MUST be zeroed after use.  
**Module:** `secure_bridge.py`, `constant_time.py`, Rust `zeroize`

### INV-14: No Persistent Secrets

```
∀ secret ∈ {password, key, plaintext}:
  secret is never written to disk unencrypted
```

**Property:** Secrets MUST NOT persist on disk.  
**Module:** All modules

### INV-15: Bounded Memory Exposure

```
∀ secret:
  time_in_python_memory(secret) is minimized
  (Rust backend reduces exposure)
```

**Property:** Secrets should spend minimal time in Python's GC heap.  
**Module:** `secure_bridge.py`

---

## Fountain Code Invariants

### INV-16: Decodability Threshold

```
∀ k_blocks, received_droplets where |received_droplets| ≥ k_blocks * 1.05:
  probability(decode_success) > 0.99
```

**Property:** With sufficient droplets, decoding MUST succeed.  
**Module:** `fountain.py`

### INV-17: Data Integrity

```
∀ original_data, decoded_data:
  sha256(original_data) = sha256(decoded_data)
```

**Property:** Decoded data MUST match original exactly.  
**Module:** `fountain.py`, `decode_gif.py`

---

## Frame Authentication Invariants

### INV-18: Frame MAC Binding

```
∀ frame_data, frame_index, master_key:
  mac = hmac(derive_frame_key(master_key, frame_index), frame_data)
```

**Property:** Each frame's MAC is bound to its index.  
**Module:** `frame_mac.py`

### INV-19: Frame Injection Rejection

```
∀ malicious_frame where mac_valid(malicious_frame) = false:
  process(malicious_frame) = reject
```

**Property:** Invalid frames MUST be rejected.  
**Module:** `frame_mac.py`, `decode_gif.py`

---

## Verification Status

| Invariant | Property Testing | Fuzzing | Formal Proof |
|-----------|------------------|---------|--------------|
| INV-1 | ✅ Hypothesis | ✅ AFL++ | ❌ Pending |
| INV-2 | ✅ Hypothesis | ✅ AFL++ | ❌ Pending |
| INV-3 | ✅ Hypothesis | ✅ AFL++ | ❌ Pending |
| INV-4 | ✅ Hypothesis | ✅ AFL++ | ❌ Pending |
| INV-5 | ✅ Hypothesis | ✅ AFL++ | ❌ Pending |
| INV-6 | ⚠️ Statistical | ❌ N/A | ❌ Pending |
| INV-7 | ✅ Unit tests | ❌ N/A | ❌ Pending |
| INV-8 | ✅ Integration | ❌ N/A | ❌ Pending |
| INV-9 | ✅ Unit tests | ❌ N/A | ❌ Pending |
| INV-10 | ✅ Chi-square | ❌ N/A | ❌ Pending |
| INV-11 | ✅ Integration | ❌ N/A | ❌ Pending |
| INV-12 | ✅ Unit tests | ❌ N/A | ❌ Pending |
| INV-13 | ⚠️ Best-effort | ❌ N/A | ❌ Platform-dependent |
| INV-14 | ✅ Manual review | ❌ N/A | ❌ Pending |
| INV-15 | ⚠️ Measured | ❌ N/A | ❌ Rust backend required |
| INV-16 | ✅ Statistical | ✅ AFL++ | ❌ Pending |
| INV-17 | ✅ Integration | ✅ AFL++ | ❌ Pending |
| INV-18 | ✅ Unit tests | ✅ AFL++ | ❌ Pending |
| INV-19 | ✅ Unit tests | ✅ AFL++ | ❌ Pending |

---

## Formal Verification Roadmap

### Phase 1: Property-Based Testing (Current)
- Hypothesis for Python invariants
- QuickCheck-style testing via Rust `proptest`

### Phase 2: Symbolic Execution (Planned)
- KLEE for C/Rust code paths
- Z3 for constraint solving

### Phase 3: Theorem Proving (Future)
- Coq/Lean for cryptographic primitives
- Focus on INV-1 through INV-6 first

### Phase 4: Model Checking (Future)
- TLA+ for protocol-level properties
- Focus on forward secrecy and ratcheting

---

## References

- [Property-Based Testing with Hypothesis](https://hypothesis.readthedocs.io/)
- [Rust proptest](https://proptest-rs.github.io/proptest/)
- [Formal Methods for Cryptography](https://csrc.nist.gov/Projects/formal-methods)
- [subtle crate - constant-time primitives](https://docs.rs/subtle/)
- [zeroize crate - secure memory zeroing](https://docs.rs/zeroize/)

---

*"Trust, but verify. Then verify again."* 🐱🔐
