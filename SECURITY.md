# 🛡️ Security Policy

**Project:** Meow Decoder  
**Version:** 5.7.0  
**Last Updated:** 2026-01-25

---

## ⚠️ **Important Security Notice**

Meow Decoder is **EXPERIMENTAL / RESEARCH-GRADE SOFTWARE** and has:
- ❌ **NOT** been formally security audited
- ❌ **NOT** been penetration tested by third parties
- ❌ **NOT** been certified for production use

**Use at your own risk. See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed security analysis.**

---

## 🐛 **Reporting Security Vulnerabilities**

We take security seriously. If you discover a security vulnerability, please follow responsible disclosure:

### **DO:**
✅ Email security details to: `security@yourdomain.com` (PGP key below)  
✅ Include detailed steps to reproduce  
✅ Include version information (`python3 encode.py --version`)  
✅ Allow us 90 days to fix before public disclosure  
✅ Encrypt sensitive details with our PGP key  

### **DON'T:**
❌ Post vulnerabilities publicly on GitHub Issues  
❌ Exploit vulnerabilities maliciously  
❌ Test on systems you don't own  
❌ Demand payment ("bug bounty" - we're open source!)  

### **Response Timeline:**
- **24 hours:** Initial acknowledgment
- **7 days:** Preliminary assessment
- **30-90 days:** Fix development and testing
- **After fix:** Public disclosure and credit

---

## 🔐 **PGP Key for Secure Reports**

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[Your PGP public key here]
-----END PGP PUBLIC KEY BLOCK-----
```

**Fingerprint:** `XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX`

---

## 🎖️ **Hall of Fame**

We thank the following security researchers for responsible disclosure:

| Researcher | Date | Vulnerability | Severity |
|------------|------|---------------|----------|
| _(No reports yet)_ | - | - | - |

---

## 🐾 **Known Security Limitations**

### **By Design:**

1. **Not Audited**
   - No formal third-party security audit
   - **Mitigation:** Use defense in depth, don't rely solely on Meow Decoder

2. **Python Implementation**
   - Not constant-time guaranteed (interpreter limitations)
   - **Mitigation:** Run on trusted hardware, avoid timing-sensitive scenarios

3. **Dependency Trust**
   - Relies on PyPI packages (cryptography, Pillow, etc.)
   - **Mitigation:** Verify package hashes, pin versions, audit dependencies

4. **No Secure Enclave**
   - Keys stored in process memory
   - **Mitigation:** Use encrypted swap, mlock, secure boot

### **Partial Protections:**

5. **Side-Channel Attacks**
   - Limited mitigation for timing, power, EM attacks
   - **Mitigation:** Physical security, controlled environment

6. **Memory Forensics**
   - Key zeroing helps but not perfect
   - **Mitigation:** Disable swap, use encrypted RAM disk, power off after use

7. **Endpoint Security**
   - Cannot protect against compromised OS/malware
   - **Mitigation:** Clean, hardened endpoints (Qubes OS, Tails)

---

## 📊 **Metadata Leakage Controls**

### **What Is Protected:**

1. **File Size** ✅
   - Length padding rounds to power-of-2 size classes
   - Attacker sees only the class (e.g., 1-2 MB), not exact size
   - Implementation: `metadata_obfuscation.py:add_length_padding()`

2. **Manifest Contents** ✅
   - All fields authenticated via HMAC-SHA256
   - `block_size`, `k_blocks`, `sha256` bound to HMAC
   - AAD prevents tampering with `orig_len`, `comp_len`

3. **Frame Content** ✅
   - Per-frame MAC authentication (8-byte truncated HMAC)
   - Prevents frame injection/substitution attacks
   - Implementation: `frame_mac.py`

### **What May Leak:**

1. **Approximate File Size** ⚠️
   - Frame count reveals size class (~33% granularity)
   - **Mitigation:** Chaff frames (`--chaff-frames` option, not default)

2. **Transfer Duration** ⚠️
   - Total playback time reveals data volume
   - **Mitigation:** Constant-rate streaming (use `--constant-rate`)

3. **Software Fingerprint** ⚠️
   - "MEOW" magic bytes identify format
   - **Mitigation:** Steganography mode hides in images

4. **Encoding Parameters** ⚠️
   - QR size/error correction visible in images
   - **Mitigation:** Use standard QR parameters

5. **Session Timing** ⚠️
   - Bidirectional mode ACK timing reveals RTT
   - **Mitigation:** Random delay padding (not implemented)

### **Paranoid Mode:**

For maximum metadata protection, use:
```bash
meow-encode -i secret.pdf -o secret.gif \
    --stego-mode ninja    # Hide in cat images
    --chaff-frames 20     # Add decoy frames
    --constant-rate       # Fixed timing
    --paranoid            # All obfuscation enabled
```

---

## 🔐 **Control Channel Security**

### **Bidirectional Mode Authentication:**

When using bidirectional mode (`--bidirectional`), the control channel is protected by:

1. **HKDF-Derived Session Key**
   - Derived from shared password + random session salt
   - `auth_key = HKDF(password, session_salt, "meow_bidir_auth_v1")`

2. **HMAC-SHA256 Authentication**
   - All control messages signed with auth_key
   - Truncated to 16 bytes for efficiency

3. **Replay Protection**
   - 4-byte monotonic counter prepended to all messages
   - Types protected: ACK, COMPLETION, STATUS_UPDATE, PAUSE, RESUME, RESEND_REQUEST
   - Counter must strictly increase

4. **Constant-Time Verification**
   - `secrets.compare_digest()` for all MAC comparisons
   - Prevents timing attacks on authentication

### **Security Note:**
Empty passwords trigger a `UserWarning` as control channel authentication is effectively disabled. Always use a shared password for bidirectional mode.

---

## 🔒 **Security Best Practices**

### **For Users:**

1. **Strong Passwords**
   - Use 20+ character random passwords
   - Use password managers (KeePassXC, Bitwarden)
   - Enable keyfile for 2FA

2. **Secure Endpoints**
   - Clean, updated, malware-free systems
   - Disable unnecessary services
   - Use full disk encryption

3. **Version Selection**
   - Use MEOW3 (forward secrecy) by default
   - Use MEOW4 (post-quantum) for long-term protection
   - Avoid MEOW2 (legacy, no forward secrecy)

4. **Operational Security**
   - Verify SHA-256 after decoding
   - Securely delete source files (`--wipe-source`)
   - Use steganography for plausible deniability
   - Control physical access during transfer

5. **Dependency Hygiene**
   - Verify requirements.txt hashes
   - Use virtual environments
   - Keep dependencies updated

### **For Developers:**

1. **Code Review**
   - All PRs require review
   - Focus on crypto-sensitive code
   - Use static analysis tools (bandit, mypy)

2. **Testing**
   - Maintain >80% test coverage
   - Include crypto roundtrip tests
   - Test error conditions

3. **Dependency Updates**
   - Monitor security advisories
   - Update dependencies promptly
   - Test after updates

4. **Changelog**
   - Document all security-relevant changes
   - Tag security releases clearly

---

## 🔍 **Vulnerability Categories**

We're particularly interested in reports for:

### **Critical** (Immediate fix)
- Remote code execution
- Authentication bypass
- Key extraction vulnerabilities
- Cryptographic implementation flaws

### **High** (Fix within 7 days)
- Denial of service
- Information disclosure
- Privilege escalation
- Side-channel attacks

### **Medium** (Fix within 30 days)
- Input validation issues
- Dependency vulnerabilities
- Memory leaks

### **Low** (Fix when convenient)
- Documentation errors
- Non-security bugs
- UI/UX issues

---

## 🛠️ **Security Fixes**

### **v5.7.0 (2026-01-25)**
- ✅ Extended replay protection to all control message types
- ✅ Added `pip-audit` to CI for Python dependency scanning
- ✅ Empty password now triggers `UserWarning` in bidirectional mode
- ✅ Comprehensive control channel security tests
- ✅ Updated security documentation with metadata leakage controls

### **v5.6.0 (2026-01-25)**
- ✅ Argon2id parameters increased to 512 MiB, 20 iterations
- ✅ Post-quantum signatures (Dilithium/FIPS 204)

### **v5.5.0 (2026-01-25)**
- ✅ Duress mode for coercion resistance
- ✅ Enhanced entropy collection
- ✅ Multi-secret Schrödinger mode
- ✅ Hardware security integration (TPM/YubiKey)

### **v5.4.0 (2026-01-23)**
- ✅ Schrödinger's Yarn Ball (quantum plausible deniability)
- ✅ Decoy generation

### **v5.3.0 (2026-01-23)**
- ✅ Forward secrecy with X25519 ephemeral keys
- ✅ Frame-level MACs for DoS protection
- ✅ Constant-time operations
- ✅ Metadata obfuscation (length padding)

### **v4.0 (2026-01-22)**
- ✅ Forward secrecy enabled by default (MEOW3)
- ✅ Post-quantum support added (MEOW4)
- ✅ Enhanced steganography (Ninja Cat ULTRA)
- ✅ Streaming decode for low-memory devices
- ✅ Constant-time HMAC comparison

---

## 📚 **Security Resources**

### **Threat Model**
Read [THREAT_MODEL.md](THREAT_MODEL.md) for:
- What we protect against (7 categories)
- What we don't protect against (7 categories)
- Adversary model analysis
- Security configuration guide

### **Manifest Versioning**
Read [MANIFEST_VERSIONING.md](MANIFEST_VERSIONING.md) for:
- Formal format specifications
- Version compatibility matrix
- Security considerations per version

### **Architecture**
Read [ARCHITECTURE.md](ARCHITECTURE.md) for:
- System architecture diagram
- Data flow analysis
- Security boundaries
- Trust model

---

## 🎯 **Responsible Disclosure Examples**

### **Good Report:**
```
Subject: [SECURITY] Buffer overflow in fountain decoder

Version: 4.0
Component: fountain.py
Impact: Denial of service (crash)

Description:
When decoding with block_size=0, the decoder crashes due to
division by zero on line 123.

Steps to Reproduce:
1. Create manifest with block_size=0
2. Run decode_gif.py
3. Observe crash

Expected: Graceful error handling
Actual: Unhandled exception

Suggested Fix:
Add validation: if block_size <= 0: raise ValueError()

Contact: researcher@example.com (PGP: XXXX)
```

### **Bad Report:**
```
Subject: Your code sucks

Found a bug, give me $1000 or I'll publish it on Twitter.
```

---

## 🤝 **Credit Policy**

We credit security researchers who:
- ✅ Follow responsible disclosure
- ✅ Provide actionable reports
- ✅ Don't exploit vulnerabilities maliciously

**Credit options:**
- Name in Hall of Fame
- Name in release notes
- Name in security advisory
- Anonymous (if preferred)

---

## 📞 **Contact**

**Security Reports:** security@yourdomain.com (PGP encouraged)  
**General Questions:** GitHub Discussions  
**Bug Reports:** GitHub Issues (non-security only)

---

## 📄 **Disclosure Policy**

After a fix is released:
1. We publish a security advisory
2. We update CHANGELOG.md
3. We credit the reporter (if desired)
4. Reporter may publish their findings

**Coordinated Disclosure:** We prefer 90-day disclosure window.

---

## 🐱 **Cat-Themed Security Tip**

**"Be like a cat: Always land on your feet, even when vulnerabilities are found!"** 😺🔐

---

**Remember:** This is experimental software. Use responsibly, report issues ethically, and always assume bugs exist. Security is a journey, not a destination! 🐾

---

**Last Updated:** 2026-01-25  
**Version:** 5.7.0  
**Status:** Research/Educational - Not Audited
