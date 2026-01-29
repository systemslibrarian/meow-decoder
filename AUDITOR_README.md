# 🔍 Meow Decoder - Auditor's Guide

## Executive Summary

**Project:** Meow Decoder - Optical Air-Gap File Transfer System  
**Version:** 6.0 (Security-Reviewed v1.0)  
**Language:** Python 3.10+ / Rust 1.70+  
**Crypto Primitives:** AES-256-GCM, Argon2id, X25519, ML-KEM-768/1024, Ed25519, Dilithium3, HMAC-SHA256  
**Lines of Code:** ~12,000 Python, ~3,000 Rust  

---

## Quick Start for Auditors

### 1. Clone and Setup (5 minutes)

```bash
git clone https://github.com/YOUR_USERNAME/meow-decoder.git
cd meow-decoder

# Python environment
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Rust backend (required for constant-time operations)
cargo build --release
```

### 2. Run Security Test Suite (10 minutes)

```bash
# Full security test suite
make test-security

# Adversarial input tests
pytest tests/test_adversarial.py -v

# Cryptographic tests
pytest tests/test_security.py tests/test_crypto.py -v

# Hardware integration tests (mocked)
pytest tests/test_hardware_integration.py -v
```

### 3. Static Analysis (5 minutes)

```bash
# Python security linting
bandit -r meow_decoder/ -ll

# Rust security audit
cd crypto_core && cargo audit && cd ..

# Type checking
mypy meow_decoder/ --strict
```

---

## Architecture Overview

### Data Flow

```
┌────────────────────────────────────────────────────────────────────────┐
│                           ENCODING PIPELINE                           │
│                                                                        │
│  File → Compress (zlib) → Encrypt (AES-256-GCM) → Fountain (LT)      │
│       → QR Codes → GIF Animation                                      │
│                                                                        │
│  Key Derivation:                                                       │
│    Password + Salt → Argon2id (512 MiB, 20 iter) → Master Key        │
│    [Optional] + X25519 Ephemeral → Shared Secret (Forward Secrecy)   │
│    [Optional] + YubiKey/HSM/TPM → Hardware-Backed Key                │
│                                                                        │
│  Authentication:                                                       │
│    Master Key → HKDF → HMAC Key → HMAC-SHA256(Manifest)             │
│    Master Key → HKDF → Frame MAC Key → Per-Frame 8-byte MACs         │
└────────────────────────────────────────────────────────────────────────┘
```

### Manifest Format (MEOW3/MEOW4)

```
┌────────────────────────────────────────────────────────────────────────┐
│  MAGIC (5B) │ Salt (16B) │ Nonce (12B) │ Lengths (12B) │ SHA256 (32B) │
├────────────────────────────────────────────────────────────────────────┤
│  HMAC (32B) │ [Ephemeral PubKey (32B)] │ [PQ Ciphertext (1088B)]      │
├────────────────────────────────────────────────────────────────────────┤
│  [Duress Tag (32B)]                                                    │
└────────────────────────────────────────────────────────────────────────┘

Total sizes:
  - MEOW2 (password-only):      115 bytes
  - MEOW3 (forward secrecy):    147 bytes
  - MEOW3 + duress:             179 bytes
  - MEOW4 (post-quantum):       1235 bytes
  - MEOW4 + duress:             1267 bytes
```

---

## Critical Code Paths

### 1. Key Derivation (`crypto.py:derive_key`)

**Location:** `meow_decoder/crypto.py` lines 155-200

**Security Properties:**
- Memory-hard: 512 MiB (8x OWASP minimum)
- Time-hard: 20 iterations (~5-10 sec on modern hardware)
- Side-channel resistant: Timing via Rust backend

**Review Focus:**
- [ ] Salt length validation (must be 16 bytes)
- [ ] Password minimum length (8 chars enforced)
- [ ] Keyfile combination via HKDF
- [ ] Secure memory cleanup

### 2. Encryption (`crypto.py:encrypt_file_bytes`)

**Location:** `meow_decoder/crypto.py` lines 235-320

**Security Properties:**
- AES-256-GCM with 96-bit nonce (never reused)
- AAD includes: orig_len, comp_len, salt, sha256, magic
- Nonce reuse guard (per-process cache)

**Review Focus:**
- [ ] Nonce generation (secrets.token_bytes)
- [ ] AAD construction completeness
- [ ] Forward secrecy key agreement
- [ ] Ephemeral key destruction

### 3. Manifest HMAC (`crypto.py:compute_manifest_hmac`)

**Location:** `meow_decoder/crypto.py` lines 615-660

**Security Properties:**
- Domain separation: `MANIFEST_HMAC_KEY_PREFIX`
- Key derived from encryption key, not password
- Constant-time comparison

**Review Focus:**
- [ ] HMAC covers all mutable manifest fields
- [ ] Domain separation prevents cross-use
- [ ] Timing equalization on verification

### 4. Frame MAC (`frame_mac.py`)

**Location:** `meow_decoder/frame_mac.py`

**Security Properties:**
- Per-frame authentication (8-byte truncated HMAC)
- Derived from master key + salt via HKDF
- Prevents frame injection/replay

**Review Focus:**
- [ ] Frame ID binding (prevents reordering)
- [ ] Key derivation independence from manifest HMAC
- [ ] Truncation security (collision probability)

### 5. Duress Mode (`crypto.py:check_duress_password`)

**Location:** `meow_decoder/crypto.py` lines 100-130

**Security Properties:**
- Fast hash (not Argon2id) for duress check
- Constant-time comparison
- Triggers before expensive KDF

**Review Focus:**
- [ ] No timing oracle between duress and real password
- [ ] Duress tag bound to manifest core
- [ ] Decoy generation doesn't touch real ciphertext

### 6. Forward Secrecy (`x25519_forward_secrecy.py`)

**Location:** `meow_decoder/x25519_forward_secrecy.py`

**Security Properties:**
- X25519 ephemeral keypair per encryption
- Private key destroyed after use
- Shared secret via HKDF

**Review Focus:**
- [ ] Ephemeral key never persisted
- [ ] Receiver public key validation
- [ ] HKDF domain separation

### 7. Schrödinger Mode (`schrodinger_encode.py`, `quantum_mixer.py`)

**Location:** `meow_decoder/schrodinger_encode.py`, `meow_decoder/quantum_mixer.py`

**Security Properties:**
- Two independent encryptions
- Interleaved ciphertext (even=A, odd=B)
- Statistical indistinguishability

**Review Focus:**
- [ ] No cross-secret information leakage
- [ ] Entropy verification
- [ ] Independent key derivation

---

## Security Invariants

### MUST Hold

| ID | Invariant | Implementation | Test |
|----|-----------|----------------|------|
| INV-001 | Nonce never reused for same key | `_nonce_reuse_cache` | `test_security.py::test_nonce_uniqueness` |
| INV-002 | Manifest HMAC verified before decrypt | `decode_gif.py:verify_manifest_hmac` | `test_security.py::test_hmac_before_decrypt` |
| INV-003 | AAD includes all metadata | `crypto.py:encrypt_file_bytes` | `test_security.py::test_aad_completeness` |
| INV-004 | Constant-time password compare | `secrets.compare_digest` | `test_constant_time.py` |
| INV-005 | No partial plaintext on failure | AES-GCM AEAD | `test_adversarial.py` |
| INV-006 | Ephemeral keys destroyed after use | Python GC + explicit zeroing | Manual review |
| INV-007 | Duress doesn't touch real ciphertext | `duress_mode.py:get_decoy_data` | `test_duress.py` |

### SHOULD Hold (Best Effort)

| ID | Property | Implementation | Notes |
|----|----------|----------------|-------|
| BE-001 | Memory locked (mlock) | `constant_time.py:secure_memory` | Platform-dependent |
| BE-002 | Secure zeroing | `crypto_backend.secure_zero` | Python GC limitation |
| BE-003 | Timing equalization | Random delays | Statistical mitigation |

---

## Threat Model Summary

### Protected Against

✅ Passive eavesdropping (AES-256-GCM)  
✅ Brute force (Argon2id 512 MiB / 20 iter)  
✅ Ciphertext tampering (AEAD + HMAC)  
✅ Frame injection (per-frame MAC)  
✅ Forward secrecy compromise (X25519 ephemeral)  
✅ Future quantum (ML-KEM-768/1024 hybrid)  
✅ Coercion (duress + Schrödinger mode)  

### NOT Protected Against

❌ Compromised endpoint (malware)  
❌ Screen recording (optical channel visible)  
❌ Hardware side-channels (power/EM)  
❌ Rubber-hose cryptanalysis  

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for complete analysis.

---

## Formal Verification Status

| Component | Method | Status | Location |
|-----------|--------|--------|----------|
| Protocol (AEAD+HMAC) | ProVerif | ✅ Verified | `formal/proverif/` |
| Key derivation | TLA+ | ✅ Verified | `formal/tla/` |
| Fountain codes | Manual proof | ✅ Complete | `docs/formal_methods_report.md` |
| Rust primitives | Verus | 🔄 In progress | `crypto_core/` |
| Hardware sealing | TLA+ | ⬜ Planned | — |

---

## Known Issues & Mitigations

### 1. Python GC Timing

**Issue:** Python garbage collector may leave key material in memory.

**Mitigation:** 
- Explicit zeroing via `bytearray`
- mlock where available
- Rust backend for critical paths

### 2. Timing Side-Channels

**Issue:** Python can't guarantee constant-time execution.

**Mitigation:**
- `secrets.compare_digest` for comparisons
- Random delays (1-5ms jitter)
- Rust `subtle` crate for critical ops

### 3. Frame MAC Truncation

**Issue:** 8-byte MACs have collision probability 2^-64.

**Mitigation:**
- Acceptable for QR frame count (<10^6)
- Fountain redundancy handles false rejects

---

## Files Requiring Audit Focus

| Priority | File | Reason |
|----------|------|--------|
| **CRITICAL** | `meow_decoder/crypto.py` | All encryption/decryption |
| **CRITICAL** | `meow_decoder/crypto_backend.py` | Rust FFI boundary |
| **CRITICAL** | `crypto_core/src/lib.rs` | Rust crypto primitives |
| **HIGH** | `meow_decoder/frame_mac.py` | Per-frame authentication |
| **HIGH** | `meow_decoder/x25519_forward_secrecy.py` | Key exchange |
| **HIGH** | `meow_decoder/constant_time.py` | Timing mitigations |
| **MEDIUM** | `meow_decoder/schrodinger_encode.py` | Deniability |
| **MEDIUM** | `meow_decoder/duress_mode.py` | Coercion resistance |
| **MEDIUM** | `meow_decoder/hardware_integration.py` | HSM/YubiKey/TPM |

---

## Deliverables Checklist

For a complete audit, please review:

- [ ] All CRITICAL priority files
- [ ] Security test suite coverage
- [ ] Formal verification proofs
- [ ] Threat model accuracy
- [ ] Dependency security (cargo audit, pip-audit)
- [ ] Build reproducibility

---

## Contact

**Technical Lead:** [YOUR NAME]  
**Security Email:** [security@meow-decoder.example.com]  
**Repository:** [GitHub URL]

---

*Document Version: 1.0*  
*Last Updated: 2026-01-28*
