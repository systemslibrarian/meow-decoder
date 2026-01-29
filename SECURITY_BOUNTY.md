# 🐱🔐 Meow Decoder Security Bounty Program

## Overview

Meow Decoder is an optical air-gap file transfer system with cryptographic security goals suitable for life-critical data protection. We take security seriously and welcome responsible disclosure of vulnerabilities.

**Scope:** All cryptographic, authentication, and data integrity issues in the Meow Decoder project.

---

## Bounty Tiers

| Severity | Bounty Range | Examples |
|----------|--------------|----------|
| **Critical** | $2,000 - $10,000 | Key recovery without password, authentication bypass, complete confidentiality break |
| **High** | $500 - $2,000 | Partial key leakage, timing attacks leading to password recovery, manifest tampering |
| **Medium** | $100 - $500 | Information disclosure, weak entropy, DoS via crafted input |
| **Low** | $25 - $100 | Best practice violations, documentation issues with security implications |

*Note: Bounties are paid in USD via PayPal, GitHub Sponsors, or cryptocurrency (BTC/ETH) at researcher's preference.*

---

## In-Scope Vulnerabilities

### Cryptographic Issues
- [ ] Nonce reuse in AES-GCM encryption
- [ ] Key derivation weakness in Argon2id parameters
- [ ] HMAC bypass or forgery
- [ ] Frame MAC collision attacks
- [ ] Weak entropy in key/nonce generation
- [ ] Side-channel timing attacks on password verification
- [ ] Forward secrecy breaks (ephemeral key exposure)

### Authentication & Authorization
- [ ] Password bypass or oracle attacks
- [ ] Keyfile bypass
- [ ] YubiKey/HSM/TPM authentication bypass
- [ ] Duress password detection (timing oracle)
- [ ] Manifest HMAC forgery

### Data Integrity
- [ ] Undetected ciphertext tampering
- [ ] Frame injection/deletion attacks
- [ ] Fountain code manipulation (decode wrong data)
- [ ] SHA-256 hash collision exploitation

### Denial of Service
- [ ] Memory exhaustion via crafted input
- [ ] Infinite loops in fountain decoder
- [ ] QR code parsing crashes
- [ ] GIF parsing crashes

### Post-Quantum Security (MEOW4/MEOW5)
- [ ] ML-KEM-768/1024 implementation flaws
- [ ] Dilithium signature forgery
- [ ] Hybrid key exchange weaknesses

### Schrödinger Mode (Plausible Deniability)
- [ ] Statistical distinguishability attacks
- [ ] Proving second reality exists without password
- [ ] Decoy detection via metadata analysis

---

## Out of Scope

The following are **not eligible** for bounties:

- Issues requiring physical access to the device
- Social engineering attacks
- Attacks on dependencies (report upstream)
- Issues in test code only
- Already-known issues documented in THREAT_MODEL.md
- Screen recording/shoulder surfing (documented limitation)
- Endpoint compromise (malware on the machine)
- "Won't fix" items in security documentation

---

## Responsible Disclosure Guidelines

### 1. Reporting

**Email:** [security@meow-decoder.example.com] *(replace with actual contact)*

**PGP Key:** Available at `/.well-known/security.txt`

**Report should include:**
- Detailed description of vulnerability
- Steps to reproduce
- Proof of concept (code/script)
- Impact assessment
- Suggested fix (if known)

### 2. Timeline

| Phase | Duration |
|-------|----------|
| Initial response | 24 hours |
| Triage & severity assessment | 72 hours |
| Fix development | 7-30 days (severity dependent) |
| Public disclosure | 90 days from report or after fix |

### 3. Researcher Expectations

- **DO** test against your own instances only
- **DO** provide sufficient detail for reproduction
- **DO** keep findings confidential until fix is released
- **DON'T** access user data beyond minimum needed for PoC
- **DON'T** perform denial of service attacks on production systems
- **DON'T** publicly disclose before agreed timeline

### 4. Our Commitments

- Acknowledge all reports within 24 hours
- Provide status updates every 7 days during investigation
- Credit researchers in release notes (unless anonymity requested)
- Pay bounties within 30 days of fix release
- Not pursue legal action for good-faith research

---

## Hall of Fame

*Reserved for researchers who have contributed to Meow Decoder security.*

| Researcher | Contribution | Bounty Paid |
|------------|--------------|-------------|
| *Your name here* | *First verified vulnerability* | — |

---

## Technical Details for Researchers

### Architecture Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   encode.py │───▶│  crypto.py  │───▶│ fountain.py │
│   (CLI)     │    │ (AES-GCM)   │    │ (LT codes)  │
└─────────────┘    └─────────────┘    └─────────────┘
       │                  │                  │
       ▼                  ▼                  ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Rust FFI   │    │  frame_mac  │    │   QR/GIF    │
│(meow_crypto)│    │  (per-frame)│    │  encoding   │
└─────────────┘    └─────────────┘    └─────────────┘
```

### Key Files to Review

| File | Security Relevance |
|------|-------------------|
| `meow_decoder/crypto.py` | AES-GCM encryption, Argon2id KDF, HMAC |
| `meow_decoder/crypto_backend.py` | Rust FFI, constant-time operations |
| `meow_decoder/frame_mac.py` | Per-frame authentication |
| `meow_decoder/constant_time.py` | Timing attack mitigations |
| `meow_decoder/forward_secrecy.py` | X25519 ephemeral keys |
| `meow_decoder/x25519_forward_secrecy.py` | Key exchange implementation |
| `meow_decoder/schrodinger_encode.py` | Dual-reality encoding |
| `meow_decoder/quantum_mixer.py` | Statistical indistinguishability |
| `crypto_core/src/lib.rs` | Rust crypto primitives |
| `crypto_core/src/yubikey_piv.rs` | YubiKey integration |
| `crypto_core/src/hsm.rs` | HSM PKCS#11 integration |
| `crypto_core/src/tpm.rs` | TPM 2.0 integration |

### Security Invariants

See [docs/SECURITY_INVARIANTS.md](docs/SECURITY_INVARIANTS.md) for formal security properties.

Key invariants:
1. **AAD binding:** Manifest MUST be bound to ciphertext via AES-GCM AAD
2. **HMAC verification:** Compute and verify manifest HMAC before using any fields
3. **Constant-time comparisons:** Use `secrets.compare_digest()` for auth tags/passwords
4. **Nonce uniqueness:** Each encryption MUST use a unique nonce
5. **Key zeroization:** Sensitive bytes MUST be zeroed after use

### Testing Your Findings

```bash
# Set up development environment
git clone https://github.com/YOUR_USERNAME/meow-decoder.git
cd meow-decoder
pip install -e ".[dev]"
cargo build --release

# Run security tests
make test-security

# Run specific attack scenarios
pytest tests/test_adversarial.py -v
pytest tests/test_security.py -v
```

---

## Contact

**Security Email:** [security@meow-decoder.example.com]

**PGP Fingerprint:** [ADD FINGERPRINT]

**GitHub Security Advisories:** [Create Advisory](https://github.com/YOUR_USERNAME/meow-decoder/security/advisories/new)

---

*Last Updated: 2026-01-28*

*This bounty program is subject to change. Researchers are bound by the terms in effect at the time of their report.*
