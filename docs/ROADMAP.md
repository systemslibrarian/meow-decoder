# 🛡️ Security Roadmap

**Meow Decoder - Security Enhancement Roadmap**

This document outlines planned security improvements organized by timeline.

---

## ✅ Completed (v5.8.0)

### Crypto Hardening
- [x] **Argon2id Ultra-Hardened**: 512 MiB memory, 20 iterations (~5-10s per attempt)
- [x] **Post-Quantum Default**: ML-KEM-1024 + X25519 hybrid enabled by default
- [x] **Dilithium3 Signatures**: Quantum-resistant manifest authentication
- [x] **Rust Backend Required**: Constant-time operations via `subtle` crate
- [x] **Memory Zeroing**: `zeroize` crate for automatic secret cleanup

### Protocol Security
- [x] **64-bit Monotonic Counters**: Replay protection with no wrap tolerance
- [x] **Per-Frame MAC**: 8-byte HMAC-SHA256 for DoS protection
- [x] **Nonce Reuse Guard**: Per-process cache prevents AES-GCM nonce reuse
- [x] **HKDF Domain Separation**: Unique `info` strings for all subkeys
- [x] **AAD Binding**: All manifest fields bound to ciphertext

### Forward Secrecy
- [x] **X25519 Ephemeral Keys**: Generated per-encryption, never stored
- [x] **Double Ratchet**: Signal-style key evolution for streaming
- [x] **Key Zeroization**: Ephemeral keys zeroed after use

### Testing & CI
- [x] **AFL++ Fuzzing**: Continuous fuzzing for manifest/fountain/crypto
- [x] **Mutation Testing**: mutmut for crypto-critical code paths
- [x] **Security Scanning**: pip-audit, cargo-audit, Bandit in CI

---

## 🔄 Short-Term (Next Release)

### Enhanced Testing
- [x] **Property-Based Testing**: Hypothesis for invariant verification (`tests/test_property_based.py`)
- [x] **Differential Testing**: Archived after Rust-only enforcement (Python fallback removed)
- [x] **Coverage Goals**: 70%+ baseline with branch tracking on crypto-critical paths
- [x] **Hardware Mocks**: In-memory/mock HSM/YubiKey/TPM providers for CI without real devices

### Documentation
- [x] **Security Invariants Doc**: Formal listing of all security invariants (`docs/SECURITY_INVARIANTS.md`)
- [x] **Attack Surface Analysis**: Updated threat model with mitigations

---

## 🔮 Medium-Term (6-12 Months)

### Hardware Security
- [x] **HSM Integration**: PKCS#11 interface for hardware key storage
	- Implemented in `crypto_core` (feature: `hsm`); CLI wiring pending in Python layer
- [x] **YubiKey Support**: FIDO2/PIV for key derivation factor
	- Implemented in `crypto_core` (feature: `yubikey`); Python auto-detect exists, full CLI wiring pending
- [x] **TPM 2.0 Binding**: Seal keys to platform state
	- Implemented in `crypto_core` (feature: `tpm`); Python layer currently uses TPM tooling for derivation

### Rust Expansion

---
### Formal Methods
- [ ] **Formal Verification**: Verus/Coq proofs for crypto primitives
### Third-Party Audit
- [ ] **Professional Audit**: Engage security firm for full review
 [ ] Rust crypto backend for true constant-time
 [ ] Hardware security module (HSM) support
 [ ] FIDO2/WebAuthn integration
- [ ] **Penetration Testing**: Red team assessment
- [ ] **CVE Process**: Establish responsible disclosure workflow
 [ ] Formal verification of core crypto paths
 [ ] Side-channel resistant implementation
 [ ] Independent security audit

- [ ] **FIPS 140-3**: Module validation (if demand exists)
- [ ] **Common Criteria**: EAL evaluation (if demand exists)

---

| 1 | Basic encryption (AES-GCM, Argon2id) | ✅ Complete |
| 2 | Forward secrecy (X25519, ratcheting) | ✅ Complete |
| 6 | Third-party audit | 🔮 Planned |
---


For security vulnerabilities, see [SECURITY.md](../SECURITY.md) for responsible disclosure.

---

*Last Updated: January 27, 2026*

# Update pytest configuration
# Update coverage targets
# Update CI pipeline

# Mark old files as deprecated
# Add migration notes
# Remove after grace period
