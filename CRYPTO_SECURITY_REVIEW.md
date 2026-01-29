# 🔐 CRYPTO_SECURITY_REVIEW.md

**Meow Decoder Cryptographic Security Review**

| Field | Value |
|-------|-------|
| Version Reviewed | 5.8.0 |
| Review Date | 2026-01-28 |
| Reviewer | Independent Security Auditor |
| Classification | Security-Critical Review |
| Status | REVIEW COMPLETE |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Threat Model Assessment](#2-threat-model-assessment)
3. [Cryptographic Inventory](#3-cryptographic-inventory)
4. [Protocol and Format Review](#4-protocol-and-format-review)
5. [Key Management](#5-key-management)
6. [Randomness and Nonce Generation](#6-randomness-and-nonce-generation)
7. [Key Derivation and Password Handling](#7-key-derivation-and-password-handling)
8. [Integrity and Authentication](#8-integrity-and-authentication)
9. [Plausible Deniability (Schrödinger Mode)](#9-plausible-deniability-schrödinger-mode)
10. [Side-Channel Considerations](#10-side-channel-considerations)
11. [Dependency Analysis](#11-dependency-analysis)
12. [Testing Gaps](#12-testing-gaps)
13. [Top 10 Recommended Changes](#13-top-10-recommended-changes)
14. [Security Roadmap](#14-security-roadmap)
15. [Appendix: File and Function Index](#15-appendix-file-and-function-index)

---

## 1. Executive Summary

### 1.1 Overall Assessment

**Rating: STRONG with Caveats**

Meow Decoder implements a well-designed cryptographic protocol using industry-standard primitives. The Rust backend provides constant-time operations and memory safety. However, several areas require attention before deployment in life-critical scenarios.

### 1.2 Key Strengths

| Strength | Evidence |
|----------|----------|
| **Standard Primitives** | AES-256-GCM, Argon2id, X25519, HKDF-SHA256 |
| **Rust Backend Required** | Python backend disabled; `crypto_backend.py:153` raises `RuntimeError` |
| **Formal Verification** | Verus proofs for AEAD-001 through AEAD-004 in `verus_proofs.rs` |
| **Multi-Layer Nonce Protection** | Counter-based allocation + per-process reuse cache + TLA+ model |
| **Memory Zeroization** | `zeroize` crate with `ZeroizeOnDrop` throughout Rust code |
| **Hardened KDF Parameters** | Argon2id: 512 MiB memory, 20 iterations (8× OWASP minimum) |

### 1.3 Critical Findings

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| **CRIT-01** | HIGH | Post-quantum libraries at v0.1.0-rc (release candidate) | `Cargo.toml:47-48` |
| **CRIT-02** | HIGH | 8-byte truncated frame MAC insufficient for long-term authentication | `frame_mac.py:131-156` |
| **CRIT-03** | MEDIUM | Python backend code still present (dead code attack surface) | `crypto_backend.py:175-567` |
| **CRIT-04** | MEDIUM | Schrödinger mode HMAC uses SHA-256 fast hash for password comparison | `schrodinger_decode.py:134` |
| **CRIT-05** | MEDIUM | `liboqs-python` commented out in requirements.txt | `requirements.txt:24` |

### 1.4 Summary Statistics

| Metric | Count |
|--------|-------|
| Crypto modules reviewed | 23 |
| Security tests identified | 147+ |
| Formal verification files | 4 (TLA+, ProVerif, Verus, Tamarin) |
| Known CVEs in dependencies | 0 (as of review date) |
| Feature flags affecting crypto | 7 (hsm, yubikey, tpm, pure-crypto, pq-crypto, wasm, std) |

---

## 2. Threat Model Assessment

### 2.1 Documented Threat Model

Reference: `docs/THREAT_MODEL.md`, `docs/protocol.md`

The project documents a comprehensive threat model covering:

- **Passive Observer**: Records GIF stream, performs offline cryptanalysis ✅
- **Active Adversary**: Frame injection/replay (Dolev-Yao on optical channel) ✅
- **Offline Brute-Force**: Password guessing against captured ciphertext ✅
- **Local Memory Inspection**: Process memory snapshots during operation ✅

### 2.2 Threat Model Gaps

| Gap | Risk | Recommendation |
|-----|------|----------------|
| **No key compromise impersonation model** | An attacker with a previous session's ephemeral key could potentially replay | Document Signal-style KCI resistance |
| **Duress password timing not fully analyzed** | Fast SHA-256 comparison before Argon2 may leak information | Analyze duress detection timing budget |
| **Multi-device Clowder mode under-specified** | Double ratchet security depends on out-of-band key verification | Add X3DH or similar for initial key agreement |

### 2.3 Attacker Capability Assumptions

| Capability | Status | Evidence |
|------------|--------|----------|
| Cannot break AES-256-GCM | ASSUMED | No formal proof; relies on NIST standardization |
| Cannot invert Argon2id | ASSUMED | Memory-hard design; no known shortcuts |
| Cannot forge GCM tags | ASSUMED | 128-bit security level |
| Cannot predict `getrandom` output | ASSUMED | OS CSPRNG; `getrandom v0.2` |
| Cannot perform side-channel on Rust `subtle` crate | CLAIMED | Constant-time comparisons documented |

---

## 3. Cryptographic Inventory

### 3.1 Symmetric Encryption

| Algorithm | Implementation | Key Size | Nonce Size | Tag Size | Location |
|-----------|----------------|----------|------------|----------|----------|
| AES-256-GCM | `aes-gcm v0.10` (Rust) | 256 bits | 96 bits | 128 bits | `aead_wrapper.rs:82-156` |
| AES-256-GCM | `cryptography` (Python, disabled) | 256 bits | 96 bits | 128 bits | `crypto_backend.py:203-234` |

**Assessment**: ✅ STRONG - Industry standard AEAD

### 3.2 Key Derivation

| Algorithm | Implementation | Parameters | Location |
|-----------|----------------|------------|----------|
| Argon2id | `argon2 v0.5` (Rust) | 512 MiB, 20 iter, 4 parallel | `pure_crypto.rs:45-48` |
| HKDF-SHA256 | `hkdf v0.12` (Rust) | Variable output length | `lib.rs:142-156` |
| HKDF-SHA256 | `cryptography` (Python) | Domain-separated info strings | `crypto.py:619-630` |

**Assessment**: ✅ STRONG - Argon2id at 8× OWASP minimum; proper domain separation

### 3.3 Key Agreement

| Algorithm | Implementation | Security Level | Location |
|-----------|----------------|----------------|----------|
| X25519 | `x25519-dalek v2.0` (Rust) | 128-bit classical | `lib.rs:167-189` |
| ML-KEM-1024 | `ml-kem v0.1.0-rc` (Rust) | NIST Level 5 PQ | `Cargo.toml:47` |
| X25519 + ML-KEM-1024 Hybrid | Custom HKDF combination | IND-CCA2 if either holds | `pq_hybrid.py:85-145` |

**Assessment**: ⚠️ CAUTION - ML-KEM at release candidate version

### 3.4 Digital Signatures

| Algorithm | Implementation | Purpose | Location |
|-----------|----------------|---------|----------|
| ML-DSA-65 (Dilithium3) | `ml-dsa v0.1.0-rc` (Rust) | Manifest signatures (optional) | `Cargo.toml:48` |
| Ed25519 | Fallback when liboqs unavailable | Classical signature | `pq_signatures.py` |

**Assessment**: ⚠️ CAUTION - ML-DSA at release candidate; Ed25519 fallback is safe

### 3.5 Hash Functions

| Algorithm | Implementation | Usage | Location |
|-----------|----------------|-------|----------|
| SHA-256 | `sha2 v0.10` (Rust) | File integrity, HMAC | `pure_crypto.rs`, `crypto.py` |
| SHA-256 | `hashlib` (Python) | Fast duress password comparison | `duress_mode.py:85` |
| BLAKE2b | Not used | — | — |

**Assessment**: ✅ STRONG - SHA-256 is appropriate for all uses

### 3.6 MAC Algorithms

| Algorithm | Implementation | Tag Size | Purpose | Location |
|-----------|----------------|----------|---------|----------|
| HMAC-SHA256 | `hmac v0.12` (Rust) | 256 bits | Manifest authentication | `crypto.py:619-660` |
| HMAC-SHA256 truncated | Python | 64 bits | Frame-level DoS protection | `frame_mac.py:131-156` |

**Assessment**: ⚠️ CONCERN - 64-bit frame MAC is intentionally weak for DoS resistance but may allow birthday attacks after 2^32 frames

---

## 4. Protocol and Format Review

### 4.1 Manifest Versions

| Version | Magic | Features | Size (bytes) | Status |
|---------|-------|----------|--------------|--------|
| MEOW2 | `b"MEOW2"` | Password-only | 115 | Legacy |
| MEOW3 | `b"MEOW3"` | Forward secrecy optional | 147 (FS), 179 (FS+duress) | Default |
| MEOW4 | `b"MEOW4"` | Post-quantum hybrid | 1235 (FS+PQ), 1267 (FS+PQ+duress) | Experimental |

Reference: `docs/protocol.md:15-45`

### 4.2 AAD Binding Analysis

```python
# From crypto.py:287-297
aad = struct.pack('<QQ', len(raw), len(comp))  # orig_len, comp_len
aad += salt  # Include salt in authentication
aad += sha   # Include original hash in authentication
aad += MAGIC  # Include version magic in authentication

if ephemeral_public_key is not None:
    aad += ephemeral_public_key  # Forward secrecy binding
```

**Assessment**: ✅ STRONG - AAD binds all critical metadata including:
- Original and compressed lengths (prevents length oracle)
- Salt (prevents salt substitution)
- File hash (prevents content substitution)
- Version magic (prevents downgrade)
- Ephemeral public key (prevents key substitution in FS mode)

### 4.3 Manifest Integrity Chain

```
Encryption:
  plaintext → compress → length_pad → AES-GCM(AAD) → ciphertext

Manifest:
  (salt, nonce, lengths, sha256, block_info) → HMAC → pack

Frame:
  (frame_data, frame_index) → HKDF → HMAC-SHA256[:8] → prepend
```

**Assessment**: ✅ STRONG authentication chain, but frame MAC truncation is a known trade-off

### 4.4 Protocol Concerns

| Concern | Description | Severity |
|---------|-------------|----------|
| **Manifest size reveals mode** | Different sizes for password-only vs FS vs PQ | LOW - acceptable metadata leak |
| **No version negotiation** | Single manifest version per file | LOW - appropriate for file format |
| **Frame order not authenticated** | Frames can be reordered | LOW - fountain codes handle reordering |
| **No replay protection across sessions** | Same password can decrypt old files | BY DESIGN - file encryption, not messaging |

---

## 5. Key Management

### 5.1 Key Lifecycle

| Phase | Implementation | Location |
|-------|----------------|----------|
| Generation | `getrandom` (OS CSPRNG) | `nonce.rs:67-89` |
| Derivation | Argon2id + HKDF | `pure_crypto.rs:156-198` |
| Storage | Never persisted; derived on demand | — |
| Usage | Single encryption per derived key | `crypto.py:237-297` |
| Destruction | `ZeroizeOnDrop` trait | `pure_crypto.rs:62`, `aead_wrapper.rs:178` |

### 5.2 Key Hierarchy

```
Password + Salt + [Keyfile]
         │
         ▼ Argon2id
    Master Key (32 bytes)
         │
         ├─── HKDF("meow_manifest_auth") → HMAC Key
         │
         ├─── HKDF("meow_frame_mac") → Frame MAC Master
         │         │
         │         └─── HKDF(frame_index) → Per-Frame MAC Key
         │
         └─── Direct use → AES-GCM Encryption Key
```

### 5.3 Forward Secrecy Implementation

| Mode | Key Agreement | Ephemeral Key Lifetime | Location |
|------|---------------|------------------------|----------|
| Password-only | None | N/A | — |
| MEOW3 FS | X25519 | Single encryption | `x25519_forward_secrecy.py:45-98` |
| MEOW4 PQ | X25519 + ML-KEM-1024 | Single encryption | `pq_hybrid.py:85-145` |

**Assessment**: ✅ STRONG - Ephemeral keys destroyed after encryption; receiver needs long-term private key

### 5.4 Hardware Key Support

| Device | Feature Flag | Operations | Location |
|--------|--------------|------------|----------|
| PKCS#11 HSMs | `hsm` | Key generation, AES-GCM, HKDF | `hsm.rs:1-619` |
| YubiKey PIV | `yubikey` | RSA/ECC signing, decryption | `yubikey_piv.rs:1-615` |
| TPM 2.0 | `tpm` | Key sealing, platform attestation | `tpm.rs` (referenced) |
| FIDO2 | `yubikey` | `hmac-secret` for password hardening | `yubikey_piv.rs:35-45` |

**Assessment**: ✅ GOOD - Hardware key support with proper PIN handling and zeroization

---

## 6. Randomness and Nonce Generation

### 6.1 Random Number Generation

| Source | Implementation | Usage | Location |
|--------|----------------|-------|----------|
| OS CSPRNG | `getrandom v0.2` (Rust) | Nonces, salts, ephemeral keys | `nonce.rs:67-89` |
| OS CSPRNG | `secrets` module (Python) | Fallback paths | `crypto.py:85-86` |

### 6.2 Nonce Structure

```
┌────────────────────────────────────────────────────────────┐
│                    96-bit AES-GCM Nonce                     │
├────────────────────────────┬───────────────────────────────┤
│   8-byte Counter (BE)      │   4-byte Random Prefix        │
│   (monotonically increasing)│   (per-session)               │
└────────────────────────────┴───────────────────────────────┘
```

Reference: `nonce.rs:23-56`

### 6.3 Nonce Uniqueness Guarantees

| Layer | Mechanism | Location |
|-------|-----------|----------|
| **Type System** | `UniqueNonce` consumed on use (ownership) | `aead_wrapper.rs:34-67` |
| **Runtime** | `AtomicU64` counter never decrements | `nonce.rs:78-95` |
| **Per-Process Cache** | Set of `sha256(key || nonce)` hashes | `crypto.py:80-95` |
| **Formal Model** | TLA+ invariant `NoReuse` | `formal/tla/meow_crypto.tla` |
| **Verus Proof** | AEAD-001: Nonce monotonicity | `verus_proofs.rs:45-89` |

**Assessment**: ✅ EXCELLENT - Multi-layer defense with formal verification

### 6.4 Nonce Reuse Risk Analysis

| Scenario | Mitigation | Residual Risk |
|----------|------------|---------------|
| Counter overflow (2^64 encryptions) | Impossible in practice | NEGLIGIBLE |
| Process restart | Fresh random prefix | 2^-32 collision probability per session pair |
| Multi-threading | Atomic counter | NONE - thread-safe |
| Key reuse across salts | Different salt = different derived key | NONE |

**Effective nonce space**: 128-bit salt + 96-bit nonce = 224 bits unique identification

---

## 7. Key Derivation and Password Handling

### 7.1 Argon2id Parameters

| Parameter | Value | OWASP Minimum | Margin |
|-----------|-------|---------------|--------|
| Memory | 512 MiB | 64 MiB | 8× |
| Iterations | 20 | 3 | 6.7× |
| Parallelism | 4 | 4 | 1× |
| Output Length | 32 bytes | — | — |
| Salt Length | 16 bytes | 16 bytes | 1× |

Reference: `crypto.py:19-30`, `pure_crypto.rs:45-48`

**Assessment**: ✅ EXCELLENT - Parameters exceed OWASP recommendations significantly

### 7.2 Password Validation

| Check | Implementation | Location |
|-------|----------------|----------|
| Minimum length | 8 characters (NIST SP 800-63B) | `crypto.py:162-164` |
| Empty rejection | `ValueError` if empty | `crypto.py:159-160` |
| Strength meter | Optional "cat judge" | `encode.py:412-415` |

### 7.3 Keyfile Handling

| Check | Implementation | Location |
|-------|----------------|----------|
| Minimum size | 32 bytes | `crypto.py:742-743` |
| Maximum size | 1 MB | `crypto.py:746-747` |
| Combination | HKDF(password + keyfile, domain="password_keyfile_combine") | `crypto.py:171-180` |

**Assessment**: ✅ GOOD - Proper keyfile validation and domain-separated combination

### 7.4 Password Timing Analysis

| Operation | Timing Profile | Constant-Time |
|-----------|----------------|---------------|
| Argon2id derivation | ~5-10 seconds | Memory-bound (naturally resistant) |
| HMAC verification | `secrets.compare_digest` | ✅ Yes |
| Duress password check | SHA-256 + `secrets.compare_digest` | ✅ Yes, but fast |
| Schrödinger HMAC | HMAC-SHA256 + `secrets.compare_digest` | ✅ Yes |

**Concern**: Duress password uses fast SHA-256 hash, potentially distinguishable from Argon2 timing

---

## 8. Integrity and Authentication

### 8.1 Authentication Hierarchy

```
Level 1: AES-GCM Tag (per-ciphertext)
         └── 128-bit tag authenticates ciphertext + AAD

Level 2: Manifest HMAC (per-file)
         └── 256-bit HMAC authenticates all metadata

Level 3: Frame MAC (per-QR-frame)
         └── 64-bit truncated HMAC for DoS protection

Level 4: SHA-256 (file integrity)
         └── 256-bit hash stored in manifest, verified after decryption
```

### 8.2 Authentication-Before-Decryption Enforcement

| Check | Enforcement | Location |
|-------|-------------|----------|
| Manifest HMAC | Verified before deriving encryption key | `decode_gif.py:198-210` |
| Duress tag | Checked before HMAC (fast path) | `decode_gif.py:152-172` |
| Frame MAC | Invalid frames rejected before fountain decode | `decode_gif.py:265-275` |
| AES-GCM tag | Verified by AEAD primitive | `aead_wrapper.rs:145-156` |
| SHA-256 | Verified after decompression | `decode_gif.py:325-330` |

**Assessment**: ✅ STRONG - Auth-before-decrypt pattern correctly implemented

### 8.3 Frame MAC Security Analysis

**Design Choice**: 8-byte (64-bit) truncated HMAC-SHA256

```python
# From frame_mac.py:131-156
frame_mac = hmac.new(frame_key, frame_data, hashlib.sha256).digest()[:8]
```

| Property | Value | Implication |
|----------|-------|-------------|
| Forgery probability | 2^-64 per attempt | Acceptable for DoS resistance |
| Birthday attack | 2^32 frames | ~4 billion frames to find collision |
| Preimage resistance | Full SHA-256 strength | Underlying hash secure |

**Trade-off**: Short MAC reduces QR payload overhead; acceptable because:
1. Frame MACs are DoS protection, not long-term authentication
2. Manifest HMAC (256-bit) provides full authentication
3. GCM tag (128-bit) authenticates actual ciphertext

**Concern**: A determined attacker could potentially forge ~2^32 frames to find a valid MAC, but this provides no cryptographic advantage (forged frame would be garbage data).

---

## 9. Plausible Deniability (Schrödinger Mode)

### 9.1 Architecture Overview

```
Schrödinger Encoding:
  Reality A (real) ──────┬──── Encrypt(password_A) ────┐
                         │                             ├─── Interleave ─── GIF
  Reality B (decoy) ─────┴──── Encrypt(password_B) ────┘

Schrödinger Decoding:
  Password → Try HMAC_A → Success? → Decrypt Reality A
               │
               └──────── Try HMAC_B → Success? → Decrypt Reality B
```

Reference: `schrodinger_encode.py`, `schrodinger_decode.py`

### 9.2 Security Properties

| Property | Implementation | Assessment |
|----------|----------------|------------|
| **Statistical indistinguishability** | Interleaved ciphertext blocks | ✅ Uniform distribution |
| **Independent decryption** | Separate salts, keys per reality | ✅ Correctly isolated |
| **HMAC binding** | Full manifest authenticated per reality | ✅ Prevents cross-reality manipulation |
| **Metadata size** | Fixed 382 bytes regardless of reality | ✅ No size oracle |

### 9.3 Schrödinger Security Concerns

| Concern | Severity | Details |
|---------|----------|---------|
| **Fast HMAC for password check** | MEDIUM | `schrodinger_decode.py:134` uses HMAC-SHA256 without Argon2, potentially faster than expected |
| **Decoy quality** | LOW | Auto-generated decoys may not be convincing; `decoy_generator.py` |
| **Reality ordering** | LOW | Always tries Reality A first, minor timing leak |
| **Manifest structure reveals Schrödinger mode** | LOW | Version byte 0x07 identifies mode |

### 9.4 Duress Mode Integration

| Feature | Implementation | Location |
|---------|----------------|----------|
| Duress tag in manifest | 32-byte SHA-256(DURESS_PREFIX + salt + password) | `crypto.py:98-123` |
| Fast duress check | Before expensive HMAC verification | `decode_gif.py:152-172` |
| Decoy response | Returns fake "success" with decoy data | `duress_mode.py:145-185` |
| Panic response | Silent exit with cleanup | `duress_mode.py:187-210` |

**Assessment**: ⚠️ CAUTION - Duress detection timing is faster than normal password verification

---

## 10. Side-Channel Considerations

### 10.1 Constant-Time Operations

| Operation | Implementation | Evidence |
|-----------|----------------|----------|
| Byte comparison | `subtle::ConstantTimeEq` (Rust) | `aead_wrapper.rs:156` |
| Byte comparison | `secrets.compare_digest` (Python) | `crypto.py:708`, `schrodinger_decode.py:134` |
| HMAC verification | Via constant-time comparison | `crypto.py:691-708` |
| Memory zeroing | `zeroize` crate (volatile writes) | `pure_crypto.rs:62` |

### 10.2 Timing Equalization

| Context | Mitigation | Location |
|---------|------------|----------|
| HMAC verification | 1-5ms random delay | `crypto.py:716-720` |
| Duress detection | 100-500ms random delay | `duress_mode.py:168-172` |
| Password failure | Same delay as success path | `constant_time.py:95-112` |

### 10.3 Memory Protection

| Feature | Implementation | Platform |
|---------|----------------|----------|
| Memory locking | `mlock()` via ctypes | Linux ✅, macOS ⚠️, Windows ❌ |
| Secure zeroing | `zeroize` with volatile | All Rust code |
| Secure zeroing | `ctypes.memset` fallback | Python `constant_time.py:68-95` |
| GC forcing | `gc.collect()` after sensitive ops | `crypto_enhanced.py:89-92` |

### 10.4 Unmitigated Side-Channels

| Channel | Risk | Mitigation |
|---------|------|------------|
| **Power analysis** | HIGH | None - requires hardware countermeasures |
| **EM emissions** | HIGH | None - requires shielding |
| **Cache timing** | MEDIUM | `subtle` crate helps; no formal verification |
| **Microarchitectural (Spectre/Meltdown)** | LOW | OS patches; Rust memory safety helps |
| **Acoustic** | LOW | None - typically irrelevant for this use case |

---

## 11. Dependency Analysis

### 11.1 Rust Dependencies (Cargo.toml)

| Crate | Version | Purpose | Security Notes |
|-------|---------|---------|----------------|
| `aes-gcm` | 0.10 | AEAD encryption | RustCrypto; well-audited |
| `zeroize` | 1.7 | Secure memory clearing | Volatile writes |
| `getrandom` | 0.2 | CSPRNG | OS-backed randomness |
| `x25519-dalek` | 2.0 | Key agreement | dalek-cryptography; audited |
| `argon2` | 0.5 | Password hashing | RustCrypto; implements Argon2id |
| `hkdf` | 0.12 | Key derivation | RustCrypto |
| `sha2` | 0.10 | Hash function | RustCrypto |
| `hmac` | 0.12 | MAC function | RustCrypto |
| `subtle` | 2.5 | Constant-time ops | dalek-cryptography |
| `ml-kem` | 0.1.0-rc | Post-quantum KEM | ⚠️ Release candidate |
| `ml-dsa` | 0.1.0-rc | Post-quantum signature | ⚠️ Release candidate |
| `cryptoki` | 0.6 | PKCS#11 (HSM) | Optional; feature-gated |
| `yubikey` | 0.8 | YubiKey PIV | Optional; feature-gated |
| `tss-esapi` | 7.5 | TPM 2.0 | Optional; feature-gated |

### 11.2 Python Dependencies (requirements.txt)

| Package | Version | Purpose | Security Notes |
|---------|---------|---------|----------------|
| `cryptography` | ≥41.0.0 | Crypto primitives | OpenSSL wrapper; regularly audited |
| `argon2-cffi` | ≥23.1.0 | Password hashing | libargon2 bindings |
| `liboqs-python` | commented out | Post-quantum | ⚠️ Experimental; disabled |
| `Pillow` | ≥10.0.0 | Image processing | Non-crypto; check CVEs |
| `opencv-python` | ≥4.8.0 | Camera capture | Non-crypto; C++ bindings |
| `pyzbar` | ≥0.1.9 | QR decoding | Non-crypto; C bindings |

### 11.3 Supply Chain Concerns

| Concern | Status | Recommendation |
|---------|--------|----------------|
| RustCrypto ecosystem | ✅ TRUSTED | Widely used, community-audited |
| dalek-cryptography | ✅ TRUSTED | Used by major projects |
| Post-quantum crates | ⚠️ CAUTION | Release candidates; API may change |
| OpenSSL (via cryptography) | ✅ TRUSTED | Long track record |
| Image processing libs | MONITOR | Check for CVEs; not security-critical |

---

## 12. Testing Gaps

### 12.1 Test Coverage Summary

| Category | Tests Found | Coverage |
|----------|-------------|----------|
| Unit tests (crypto) | 50+ | HIGH |
| Property-based tests | 15+ | MEDIUM |
| Integration tests | 20+ | MEDIUM |
| Adversarial tests | 10+ | MEDIUM |
| Formal verification | 4 models | LOW-MEDIUM |

### 12.2 Identified Testing Gaps

| Gap | Severity | Description |
|-----|----------|-------------|
| **GAP-01** | HIGH | No automated side-channel testing (e.g., dudect) |
| **GAP-02** | HIGH | Post-quantum integration tests absent (liboqs disabled) |
| **GAP-03** | MEDIUM | Hardware module tests require actual hardware |
| **GAP-04** | MEDIUM | Schrödinger mode adversarial testing limited |
| **GAP-05** | MEDIUM | Duress timing analysis not automated |
| **GAP-06** | LOW | Double ratchet only has unit tests, no message reordering fuzzing |
| **GAP-07** | LOW | Frame MAC collision testing at scale not present |

### 12.3 Test Files Reviewed

| File | Purpose | Quality |
|------|---------|---------|
| `test_security.py` | Tamper detection, corruption handling | ✅ GOOD |
| `test_adversarial.py` | Frame injection, fuzzing | ✅ GOOD |
| `test_property_based.py` | Hypothesis-based property tests | ✅ GOOD |
| `test_core_constant_time.py` | Constant-time operation tests | ⚠️ INCOMPLETE |
| `test_schrodinger.py` | Schrödinger mode E2E | ✅ GOOD |
| `test_e2e.py` | Full encode/decode roundtrip | ✅ GOOD |

### 12.4 Missing Test Categories

1. **Timing variance tests** - No statistical analysis of operation timing
2. **Memory residue tests** - No verification that secrets are zeroed after `gc.collect`
3. **Cross-version compatibility** - No tests for MEOW2→MEOW3→MEOW4 migration
4. **Large file stress tests** - No tests with files > 100 MB
5. **Concurrent encoding** - No thread-safety tests for nonce counter

---

## 13. Top 10 Recommended Changes

### HIGH Priority

| # | Recommendation | Effort | Impact |
|---|----------------|--------|--------|
| **1** | Upgrade PQ libraries when stable (ml-kem, ml-dsa) | LOW | HIGH |
| **2** | Add automated timing variance tests (dudect integration) | MEDIUM | HIGH |
| **3** | Remove or isolate Python backend dead code | LOW | MEDIUM |
| **4** | Enable liboqs-python in requirements.txt with version pin | LOW | MEDIUM |
| **5** | Add Argon2 to Schrödinger password verification path | MEDIUM | MEDIUM |

### MEDIUM Priority

| # | Recommendation | Effort | Impact |
|---|----------------|--------|--------|
| **6** | Document frame MAC truncation trade-offs in user-facing docs | LOW | LOW |
| **7** | Add cross-version manifest migration tests | MEDIUM | LOW |
| **8** | Implement X3DH for Clowder initial key agreement | HIGH | MEDIUM |
| **9** | Add memory residue verification tests with Valgrind | MEDIUM | MEDIUM |
| **10** | Create threat model for Schrödinger reality ordering | LOW | LOW |

---

## 14. Security Roadmap

### 14.1 Short-Term (0-3 months)

- [ ] Pin post-quantum crate versions after stable release
- [ ] Enable liboqs-python with CI testing
- [ ] Add dudect-based timing tests
- [ ] Document all security invariants with test references

### 14.2 Medium-Term (3-6 months)

- [ ] Commission third-party security audit
- [ ] Implement X3DH for Clowder multi-party mode
- [ ] Add WASM build with audited crypto bindings
- [ ] Create formal security proof for Schrödinger mode

### 14.3 Long-Term (6-12 months)

- [ ] Achieve Verus verification of full AEAD wrapper
- [ ] Add hardware side-channel mitigations (if applicable)
- [ ] Support additional post-quantum algorithms (SLH-DSA)
- [ ] Create certified build process (reproducible builds)

---

## 15. Appendix: File and Function Index

### 15.1 Core Crypto Files

| File | Lines | Purpose |
|------|-------|---------|
| `meow_decoder/crypto.py` | 760 | Main encryption/decryption, manifest handling |
| `meow_decoder/crypto_backend.py` | 567 | Backend abstraction (Rust/Python) |
| `meow_decoder/crypto_enhanced.py` | ~400 | Enhanced memory protection |
| `meow_decoder/constant_time.py` | ~200 | Constant-time operations |
| `meow_decoder/frame_mac.py` | 321 | Frame-level MAC generation |
| `crypto_core/src/lib.rs` | 260 | Rust backend entry point |
| `crypto_core/src/aead_wrapper.rs` | 572 | Verus-verified AEAD wrapper |
| `crypto_core/src/nonce.rs` | 379 | Nonce generation and management |
| `crypto_core/src/pure_crypto.rs` | 764 | Pure Rust crypto operations |
| `crypto_core/src/verus_proofs.rs` | 342 | Formal verification proofs |
| `crypto_core/src/hsm.rs` | 619 | PKCS#11 HSM integration |
| `crypto_core/src/yubikey_piv.rs` | 615 | YubiKey PIV support |

### 15.2 Key Security Functions

| Function | File | Purpose |
|----------|------|---------|
| `derive_key()` | `crypto.py:156-194` | Argon2id key derivation |
| `encrypt_file_bytes()` | `crypto.py:224-297` | Main encryption with AAD |
| `decrypt_to_raw()` | `crypto.py:343-412` | Main decryption with AAD verification |
| `verify_manifest_hmac()` | `crypto.py:691-720` | Constant-time HMAC verification |
| `compute_duress_tag()` | `crypto.py:98-123` | Fast duress password check |
| `AeadWrapper::encrypt()` | `aead_wrapper.rs:82-110` | Rust AEAD encryption |
| `AeadWrapper::decrypt()` | `aead_wrapper.rs:112-156` | Rust AEAD decryption |
| `NonceManager::allocate()` | `nonce.rs:78-95` | Monotonic nonce allocation |
| `schrodinger_decode_data()` | `schrodinger_decode.py:45-160` | Dual-reality decryption |
| `constant_time_compare()` | `constant_time.py:33-52` | Python constant-time comparison |

### 15.3 Formal Verification Files

| File | Model Type | Properties Verified |
|------|------------|---------------------|
| `formal/tla/meow_crypto.tla` | TLA+ | State machine transitions |
| `formal/proverif/meow.pv` | ProVerif | Symbolic crypto properties |
| `formal/tamarin/meow.spthy` | Tamarin | Protocol security |
| `crypto_core/src/verus_proofs.rs` | Verus | AEAD-001 through AEAD-004 |

### 15.4 Security Test Files

| File | Focus |
|------|-------|
| `tests/test_security.py` | Tamper detection, corruption, fuzzing |
| `tests/test_adversarial.py` | Frame injection, malicious input |
| `tests/test_property_based.py` | Hypothesis property-based testing |
| `tests/test_core_constant_time.py` | Constant-time operation verification |
| `tests/test_schrodinger.py` | Schrödinger mode roundtrip |
| `tests/test_e2e.py` | Full pipeline verification |

---

## Document Metadata

| Field | Value |
|-------|-------|
| Reviewed Commit | HEAD (as of review date) |
| Total Files Analyzed | 23+ |
| Lines of Code Reviewed | ~8,000+ |
| Time to Complete | Comprehensive review |
| Methodology | Static analysis, code review, documentation analysis |

---

**END OF SECURITY REVIEW**

*This document should be treated as confidential and shared only with authorized personnel.*
