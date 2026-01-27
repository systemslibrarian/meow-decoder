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

## 🧪 Formal Methods (What is Actually Proven)

We use multiple formal methods with **conservative claims**:

| Method | What it proves | Assumptions |
|---|---|---|
| **TLA+ (TLC)** | State‑machine safety invariants (auth‑then‑output, replay rejection, duress behavior) | Abstract crypto; bounded model checking |
| **ProVerif** | Symbolic secrecy/authentication properties under Dolev‑Yao attacker | Perfect cryptography; symbolic model |
| **Tamarin (optional)** | Minimal observational equivalence check (real vs decoy abstraction) | Abstract crypto; minimal model |
| **Verus** | Crypto wrapper invariants (nonce uniqueness, auth‑then‑output, key zeroization) | AES‑GCM security, correct RNG |

**Not proven:** AES‑GCM primitive correctness, side‑channel resistance, or compromised host resilience.

**Reproduce:**
```bash
make verify
```

Report: [docs/formal_methods_report.md](docs/formal_methods_report.md)

---

## 🐛 **Reporting Security Vulnerabilities**

We take security seriously. If you discover a security vulnerability, please follow responsible disclosure:

### **DO:**
✅ Email security details to: `systemslibrarian@gmail.com`  
✅ Include detailed steps to reproduce  
✅ Include version information (`python3 encode.py --version`)  
✅ Allow us 90 days to fix before public disclosure  
✅ Include any relevant logs or repro steps  

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

6. **Steganography Limitations**
   - LSB embedding detectable by chi-square analysis, RS analysis, etc.
   - Localized embedding (`--stego-green`) may make detection EASIER
   - **Mitigation:** Use stego for cosmetic camouflage only, rely on AES-256-GCM for security
   - See: "Localized Embedding" section below

7. **Memory Forensics**
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
    - **Key separation:** Frame MAC master key is derived via HKDF from the
       encryption key (binds keyfile + forward secrecy)
    - Legacy password-only frame MAC derivation remains accepted for
       backward compatibility during decode
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

## 🌿 **Localized Embedding (Green-Region Mode)**

The `--stego-green` flag restricts LSB embedding to green-dominant pixels only
(e.g., logo eyes, wave patterns). This is available via:

```bash
meow-encode -i secret.pdf -o logo.gif \
    --stego-level 3 \
    --carrier logo.png \
    --stego-green
```

### Security Properties

| Property | Assessment |
|----------|------------|
| ✅ Visual artifacts | Reduced in non-green regions |
| ❌ Steganalysis resistance | NOT improved (may be WORSE) |
| ❌ Payload capacity | Reduced to ~10-30% |
| ❌ Detection difficulty | Concentrated modifications may be EASIER to detect |

### Why NOT More Secure?

1. **Chi-square analysis** still detects LSB modifications in green regions
2. **Histogram analysis** shows non-uniform distribution in embeddable areas
3. **Concentration effect** - embedding in fewer pixels means higher modification density
4. **Signature pattern** - consistent green-only modifications are themselves a signature

### Recommendations

- ✅ Use for **cosmetic camouflage** only (reduce visible QR artifacts)
- ✅ Combine with `--stego-level 3` or `4` for best visual results
- ❌ Do NOT rely on localized embedding for security
- ❌ Do NOT assume forensic undetectability

**The encryption (AES-256-GCM) protects your data, not the steganography.**

---

## 🔐 **Control Channel Security (Bidirectional Mode)**

## 🔍 **Crypto Design Decisions (Rationale)**

This project favors conservative, audited primitives and explicit key separation.
Design choices are documented inline in code, and summarized here for auditors.

- **AES-256-GCM**: Standard AEAD with strong confidentiality + integrity. We do not
   implement custom modes. All metadata integrity is bound via AAD.
- **Argon2id**: Memory-hard KDF with high parameters to resist GPU/ASIC attacks.
- **HKDF domain separation**: Independent subkeys are derived for encryption,
   manifest HMAC, frame MACs, and ratcheting to prevent cross-protocol key reuse.
- **Fail-closed behavior**: Any authentication failure aborts decoding with no
   plaintext output. This prevents oracle behavior and partial disclosure.
- **Forward secrecy (X25519)**: Ephemeral keys prevent future key compromise from
   decrypting historical data.
- **PQ hybrid mode**: PQ is used only for key encapsulation. If PQ is requested
   but unavailable, the operation fails closed to prevent silent downgrade.

### **Authentication Architecture:**

When using bidirectional mode (`--bidirectional`), the control channel uses cryptographic authentication to prevent spoofing and replay attacks.

**Key Derivation (HKDF-SHA256):**
```python
# Session key derived from shared password
# Exact parameters from bidirectional.py:194-203
auth_key = HKDF(
    algorithm=SHA256,
    length=32,                              # 256-bit key
    salt=session_salt,                      # 16-byte random (secrets.token_bytes(16))
    info=b"meow_bidirectional_auth_v1"      # Domain separation
).derive(password.encode('utf-8'))
```

**Message Format:**
```
┌──────────────┬────────────┬─────────────┬────────────────────┐
│ Type (1B)    │ HMAC (32B) │ Counter (8B)│ Payload (variable) │
└──────────────┴────────────┴─────────────┴────────────────────┘
```

**Message Authentication (HMAC-SHA256):**
- All control messages include HMAC: ACK, COMPLETION, STATUS_UPDATE, PAUSE, RESUME, RESEND_REQUEST
- HMAC computed over: `message_type || payload` (counter is in payload for replay-protected types)
- Full 32-byte HMAC (no truncation)
- Constant-time verification using `secrets.compare_digest()`
- Invalid HMAC → Message silently dropped (no oracle)

**Replay Protection (Monotonic Counter):**
```python
# Counter window logic from bidirectional.py:280-290
replay_protected_types = [STATUS_UPDATE, COMPLETION, PAUSE, RESUME, RESEND_REQUEST]

if msg_type in replay_protected_types:
   counter = struct.unpack('>Q', payload[:8])[0]  # 8-byte big-endian
    if counter <= last_rx_counter:
        return None  # REJECT: Replay detected (silent drop)
    last_rx_counter = counter  # Accept and advance
```

| Property | Value | Security Rationale |
|----------|-------|-------------------|
| Counter size | 8 bytes (64-bit) | Practically unlimited |
| Counter window | Strictly monotonic | `counter > last_seen` required |
| Out-of-order tolerance | **NONE** | Messages must arrive in order |
| Late message handling | **REJECTED** | Counter ≤ last_seen → drop |
| Wrap protection | **NONE** (theoretical) | Session restart before 2⁶⁴ msgs |

**Idempotent Message Types (No Counter):**
- `SESSION_ACK`, `FRAME_ACK` are safe to replay (no state change)
- These skip counter validation

**Failure Modes (Fail-Silent):**
| Condition | Behavior | Logged |
|-----------|----------|--------|
| Invalid HMAC | Message dropped | ❌ No |
| Counter ≤ last_seen | Message dropped | ❌ No |
| Payload too short | Message dropped | ❌ No |
| Missing password | `UserWarning` at init | ✅ Yes |

**Security Properties:**
- **Authentication**: Only parties with shared password can send valid control messages
- **Integrity**: Any modification to message invalidates HMAC
- **Replay Prevention**: Monotonic counter ensures each message unique
- **Timing Safety**: `secrets.compare_digest()` prevents timing oracle
- **Fail-Silent**: Invalid messages reveal no information

---

## 🔒 **Fail-Closed Manifest Integrity**

### **Guarantee: 1-Bit Flip = Complete Failure**

Meow Decoder implements **fail-closed** behavior for manifest integrity. Any modification to the manifest causes complete decryption failure with **zero information leakage**.

**Cryptographic Mechanisms:**

1. **AES-256-GCM Authenticated Encryption**
   - GCM tag binds all metadata fields
   - AAD (Additional Authenticated Data) includes:
     - Original length, compressed length, cipher length
     - Salt, nonce, SHA-256 hash
     - Magic bytes (version identifier)
     - Ephemeral public key (if forward secrecy enabled)
   - **Any bit flip in AAD or ciphertext → GCM decryption fails**

2. **HMAC-SHA256 Manifest Authentication**
   - Separate HMAC over entire manifest (excluding HMAC field itself)
   - Derived from: `HKDF(password, salt, "meow_manifest_auth_v2")`
   - Verified in constant-time before any decryption attempt
   - **HMAC mismatch → Immediate abort, no partial output**

3. **Per-Frame MAC**
    - 8-byte truncated HMAC per QR frame
    - **Current derivation:** `HKDF(encryption_key, salt, "meow_frame_mac_master_v2")`
       then per-frame HKDF with `frame_index`
    - **Legacy compatibility:** password-only derivation accepted for
       previously encoded files
    - Invalid frames silently dropped during decoding
    - **DoS protection: Malicious frames rejected before fountain decode**

**Tested Attack Vectors (see `tests/test_tamper_detection.py`):**
- ✅ Flip 1 bit in salt → Decryption fails
- ✅ Flip 1 bit in nonce → Decryption fails
- ✅ Flip 1 bit in lengths → Decryption fails
- ✅ Flip 1 bit in SHA-256 hash → Integrity check fails
- ✅ Flip 1 bit in HMAC → Authentication fails
- ✅ Swap manifest between files → HMAC mismatch, fails
- ✅ Modify ciphertext → GCM tag verification fails

**Failure Behavior:**
- No partial plaintext output
- No error messages revealing plaintext structure
- Generic error: "Decryption failed (wrong password/keyfile or tampered manifest)"
- Logs do NOT contain sensitive data

**Proof:**
```python
# From tests/test_tamper_detection.py (342 lines of tests)
def test_single_bit_flip_in_all_fields():
    """Flip 1 bit in every manifest field → all fail."""
    for field in ['salt', 'nonce', 'orig_len', 'comp_len', 'cipher_len', 'sha256', 'hmac']:
        modified_manifest = flip_bit_in_field(manifest, field, bit=0)
        with pytest.raises((RuntimeError, ValueError)):
            decrypt_to_raw(cipher, password, modified_manifest.salt, ...)
```

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

Contact: systemslibrarian@gmail.com
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

**Security Reports:** systemslibrarian@gmail.com  
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
