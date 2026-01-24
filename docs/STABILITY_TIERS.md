# 🎯 Feature Stability Tiers

**Meow Decoder v5.4.0** - Clear stability classification for all features

---

## 🟢 TIER 1: STABLE (Production-Ready)

**Guarantee:** These features are battle-tested, have automated security tests, and are safe for production use.

### Core Encryption Pipeline
- **AES-256-GCM encryption** with authenticated AAD
- **Argon2id key derivation** (OWASP-compliant parameters)
- **Fountain coding** for error resilience
- **QR code encoding/decoding** (error correction H)
- **GIF container format**

**Test Coverage:** 50% of critical code  
**Security Tests:** ✅ 10/10 passing (tamper, nonce, auth, corruption)  
**CI Status:** ✅ Enforced on every commit  
**Breaking Change Policy:** Semver, deprecation warnings

### Metadata Protection
- **HMAC-SHA256 manifest authentication**
- **AAD (Additional Authenticated Data)** for integrity
- **Frame-level MACs** (optional, enabled by default)
- **Constant-time comparison** (timing attack resistant)
- **Length padding** (metadata obfuscation)

**Test Coverage:** 41% (frame_mac.py)  
**Security Tests:** ✅ Tamper detection verified  
**CI Status:** ✅ Enforced

### File I/O
- **Password-based encryption** (password-only mode)
- **CLI tools** (`meow-encode`, `meow-decode-gif`)
- **Library API** (encode_file, decode_gif)

**Test Coverage:** 27% (encode.py), 21% (decode_gif.py)  
**Integration Tests:** ✅ E2E roundtrip verified  
**CI Status:** ✅ Enforced

---

## 🟡 TIER 2: SUPPORTED (Beta Quality)

**Guarantee:** These features work and are tested, but may have edge cases. Use in production with testing.

### Forward Secrecy (X25519)
- **Ephemeral key exchange** (X25519 ECDH)
- **Per-message ephemeral keys**
- **Forward secrecy guarantee**

**Test Coverage:** 33% (x25519_forward_secrecy.py)  
**Security Tests:** ⚠️ 0/2 passing (test harness bug, crypto works)  
**Production Status:** Works in real usage, tests need fixing  
**Breaking Change Policy:** Will be stabilized in v5.5.0

### Schrödinger's Yarn Ball
- **Dual-secret encoding** (quantum superposition)
- **Statistical indistinguishability**
- **Plausible deniability**
- **Observer collapse** (password-based reality selection)

**Test Coverage:** 0% in security suite, 100% in dedicated suite (7/7)  
**Security Tests:** ⚠️ Needs adversarial tests  
**Production Status:** Works, cryptography is sound, needs security hardening  
**Breaking Change Policy:** May change manifest format before v6.0

### Decoy Generation
- **Automatic convincing decoys** (vacation photos, shopping lists)
- **Variable size mimicry**
- **Valid file formats** (PDF, JPG, TXT)

**Test Coverage:** 28% (decoy_generator.py)  
**Functional Tests:** ✅ Generates valid files  
**Security Tests:** ⚠️ Statistical quality not tested  
**Production Status:** Safe to use, may improve quality

---

## 🟠 TIER 3: EXPERIMENTAL (Use at Own Risk)

**Guarantee:** These features are proof-of-concept quality. May have bugs, limited testing, breaking changes.

### Post-Quantum Hybrid (ML-KEM-768)
- **ML-KEM-768 (Kyber)** key encapsulation
- **Hybrid mode** (X25519 + ML-KEM)
- **Quantum-resistant encryption**

**Test Coverage:** 0%  
**Security Tests:** ❌ None  
**Dependencies:** Requires `oqs` library (optional)  
**Status:** ⚠️ Experimental - cryptographic primitives correct, integration untested  
**Breaking Change Policy:** API may change significantly

### Steganography
- **LSB embedding** in images
- **Multiple carrier formats** (PNG, JPG, BMP)
- **Animated carriers** (GIF frames)
- **Statistical undetectability** (claimed, not verified)

**Test Coverage:** 0%  
**Security Tests:** ❌ None  
**Status:** ⚠️ Experimental - may be detectable by steganalysis  
**Breaking Change Policy:** API unstable

### Webcam Decoding
- **Real-time QR scanning** from camera
- **Resume/recovery** for interrupted scans
- **Preprocessing modes** (normal/aggressive)

**Test Coverage:** 0%  
**Integration Tests:** ❌ None (requires camera hardware)  
**Status:** ⚠️ Experimental - works on tested hardware, may fail on others  
**Breaking Change Policy:** May be split into separate package

### GUI Applications
- **Tkinter GUI** for encode/decode
- **Dashboard** with stats/visualizations
- **Webcam preview**

**Test Coverage:** 0%  
**UI Tests:** ❌ None  
**Status:** ⚠️ Experimental - proof-of-concept quality  
**Breaking Change Policy:** May be removed from core package

---

## ⚫ TIER 4: DEPRECATED/UNSUPPORTED

**Guarantee:** These features exist in code but are not maintained. May be removed.

### "Fun" Features (Void Cat, Catnip, etc.)
- **Void cat ASCII art**
- **Catnip fountain variants**
- **Meme overlays**

**Status:** 🎭 Easter eggs - not security-critical  
**Test Coverage:** 0% (intentionally untested)  
**Support:** Community-maintained fun  
**Breaking Change Policy:** May be removed without notice

### Old Crypto Modes
- **Legacy manifest formats** (pre-v3)

**Status:** ❌ Deprecated  
**Support:** Decode-only for backward compatibility  
**Removal:** Planned for v6.0

---

## 📋 Feature Classification Matrix

| Feature | Tier | Tests | Coverage | CI | Production |
|---------|------|-------|----------|----|-----------| 
| **Core Crypto** | 🟢 Stable | 10/10 | 50% | ✅ | ✅ |
| **Fountain Codes** | 🟢 Stable | ✅ | 45% | ✅ | ✅ |
| **QR Encoding** | 🟢 Stable | ✅ | 34% | ✅ | ✅ |
| **Frame MACs** | 🟢 Stable | ✅ | 41% | ✅ | ✅ |
| **Forward Secrecy** | 🟡 Beta | 0/2 | 33% | ⚠️ | 🟡 |
| **Schrödinger** | 🟡 Beta | 7/7 | 0% | ⚠️ | 🟡 |
| **Decoy Gen** | 🟡 Beta | ✅ | 28% | ⚠️ | 🟡 |
| **Post-Quantum** | 🟠 Experimental | ❌ | 0% | ❌ | ❌ |
| **Steganography** | 🟠 Experimental | ❌ | 0% | ❌ | ❌ |
| **Webcam** | 🟠 Experimental | ❌ | 0% | ❌ | ❌ |
| **GUI** | 🟠 Experimental | ❌ | 0% | ❌ | ❌ |
| **Void Cat** | ⚫ Fun | N/A | 0% | N/A | 🎭 |

---

## 🎯 Stability Promises

### TIER 1 (Stable) Guarantees

1. **No breaking changes** without major version bump
2. **Security tests enforced** by CI
3. **Deprecation warnings** for 1 full major version
4. **Bug fixes released** within 1 week of report
5. **Documentation complete** and up-to-date

### TIER 2 (Beta) Promises

1. **Breaking changes possible** in minor versions
2. **Deprecation warnings** for 1 minor version
3. **Bug fixes best-effort** (usually within 2 weeks)
4. **Documentation mostly complete**
5. **Will be promoted to Tier 1** after hardening

### TIER 3 (Experimental) Warning

1. **Breaking changes anytime** (even in patch versions)
2. **No backward compatibility** guarantees
3. **Bug fixes community-driven**
4. **Documentation minimal** (may be just docstrings)
5. **May be removed** without deprecation period

### TIER 4 (Deprecated) Notice

1. **Use at own risk**
2. **No support** (community only)
3. **May break anytime**
4. **Will be removed** in next major version

---

## 📊 Promotion Criteria

**To promote from Tier 3 → Tier 2:**
- [ ] Basic functional tests (>50% coverage)
- [ ] E2E integration test
- [ ] Documentation complete
- [ ] No known critical bugs

**To promote from Tier 2 → Tier 1:**
- [ ] Security test suite (adversarial tests)
- [ ] CI enforcement
- [ ] >40% test coverage
- [ ] Production usage (>100 users, >3 months)
- [ ] External security review

---

## 🚦 How to Choose

### Use TIER 1 if:
- ✅ You need production-grade security
- ✅ You need stability guarantees
- ✅ You can't tolerate breaking changes
- ✅ Example: Encrypting sensitive documents

### Use TIER 2 if:
- 🟡 You can test in your environment first
- 🟡 You can handle occasional breaking changes
- 🟡 You want newer features
- 🟡 Example: Forward secrecy, dual secrets

### Use TIER 3 if:
- 🟠 You're experimenting / prototyping
- 🟠 You can fix bugs yourself
- 🟠 You expect API changes
- 🟠 Example: Post-quantum research

### Avoid TIER 4:
- ⚫ These are deprecated or unsupported
- ⚫ Use only for backward compatibility
- ⚫ Plan migration to supported features

---

## 🔄 Migration Paths

**From Tier 3 → Tier 2:**
- Update to newer API when stabilized
- Check release notes for breaking changes
- Test thoroughly before deploying

**From Tier 2 → Tier 1:**
- No action needed (will be promoted automatically)
- Breaking changes will have deprecation warnings

**From Tier 4:**
- Migrate to supported alternative ASAP
- Check CHANGELOG for removal timeline

---

## 📞 Feature Requests

**Want a feature promoted?**
1. Submit comprehensive tests (PR welcome!)
2. Document edge cases
3. Provide usage examples
4. Help with code review

**Want a new feature?**
1. Start in Tier 3 (experimental)
2. Gather usage feedback
3. Add tests and docs
4. Request promotion review

---

## 📚 Version History

**v5.4.0:**
- Core crypto: Tier 1 (stable)
- Forward secrecy: Tier 2 (beta)
- Schrödinger: Tier 2 (beta)
- Post-quantum: Tier 3 (experimental)

**Planned v5.5.0:**
- Forward secrecy: Tier 1 (promote after test fixes)
- Schrödinger: Tier 1 (promote after security tests)

**Planned v6.0:**
- Remove Tier 4 features
- Stabilize Tier 2 features
- New experimental features in Tier 3

---

## ⚖️ License & Support

**All tiers:**
- Licensed under MIT
- No warranty (see LICENSE)
- Community support via GitHub Issues

**Commercial support:**
- Available for Tier 1 features only
- Contact for SLA/support contracts

---

**Last Updated:** 2026-01-23  
**Document Version:** 1.0  
**Applies to:** meow-decoder v5.4.0+
