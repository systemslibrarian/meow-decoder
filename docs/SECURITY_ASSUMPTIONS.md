# 🔐 Security Assumptions

**Scope:** This document lists trust assumptions required for Meow Decoder to meet its stated security claims.

---

## ✅ Required Trust Assumptions

### Cryptography
- AES-256-GCM, Argon2id, HKDF, SHA-256, X25519, and ML-KEM-1024 remain secure against practical attacks.
- Authentication tags and HMACs are verified before any plaintext output.
- Nonces are never reused with the same key.

### Implementation
- Rust backend is used for constant-time operations and secure zeroing.
- Dependencies are trusted and kept patched (cryptography, argon2, pyzbar, Pillow, OpenCV).
- QR parsing and GIF decoding do not introduce exploitable memory corruption.

### Key Material
- Passwords are strong and not reused across contexts.
- Keyfiles (if used) are protected with the same operational controls as passwords.
- Forward secrecy keys are generated and discarded correctly.

### Environment & Runtime
- The sender and receiver machines are uncompromised (no malware, keyloggers, rootkits).
- OS randomness is secure (`secrets`, kernel RNG).
- No debug logs or core dumps capture secrets.

### Optical Channel
- The optical channel is observable but cannot be altered without detection (frame MACs + HMAC).
- Frame loss is tolerated within redundancy parameters.

### Operational Security
- Users understand that the phone/camera is untrusted and performs no decryption.
- Users follow safe capture workflows (no cloud auto-upload of raw recordings).

---

## ⚠️ Known Gaps / Limitations

### Side Channels
- Python fallback is not constant-time and may leak via timing or GC behavior.
- Power/EM/cache side-channel resistance is not provided.

### Endpoint Risk
- Compromised endpoints defeat all protections.
- Screen recording or shoulder-surfing trivially captures frames.

### Metadata Leakage
- Approximate size class is visible via frame count and GIF size.
- Manifest version reveals protocol capabilities.

### Schrödinger Mode
- “Neither secret can prove the other exists” is a security claim that requires independent cryptographic analysis or audit.

### Hardware Security
- HSM/YubiKey/TPM features exist in the Rust core, but full CLI wiring and operational validation are ongoing.

### Supply Chain
- No formal audit of all third-party dependencies.
- Build environment integrity is assumed.

---

## ✅ Actionable Mitigations

- Use the Rust backend only.
- Disable Python fallback in production workflows.
- Use air-gapped, trusted endpoints.
- Enable length padding / paranoid modes for metadata protection.
- Use hardware-backed keys where available and validated.

---

*Last Updated: 2026-01-28*
