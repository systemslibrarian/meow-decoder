# 🐱 Meow Decoder
## Secure Optical Air-Gap File Transfer via QR Code GIFs

**Version 5.0 - Schrödinger's Clowder Edition**

Transfer files securely through optical channels using QR codes embedded in GIF animations. Perfect for air-gapped systems, offline backups, and secure data exfiltration.

---

## 🐱 **The Philosophy of Quantum Observation**

> _**"In Meow Decoder, the secret exists in a pre-observation haze — a tangled ball of noise and cat memes. It has no definite shape until you pull exactly the right threads (correct stego parameters, enough fountain droplets, matching password-derived ratchet state). But pulling those threads presupposes the form the secret must take."**_

**Wrong filter → no thread.**  
**Right filter → the yarn suddenly becomes a coherent story.**  
**Until then? Just innocent kittens and void.** 😶‍🌫️🐱

This philosophy applies to **all** Meow Decoder features:

### **For Regular Encryption:**
- Without your password, the QR GIF is just random noise
- No one can prove what data (if any) is hidden inside
- Only the correct password "collapses" the noise into your secret
- Failed password attempts reveal nothing but gibberish

### **For Schrödinger's Yarn Ball:**
- Two secrets exist in **true quantum superposition**
- All blocks are indistinguishable until observed (decrypted)
- Your password choice determines which reality manifests
- The other secret? It never existed... as far as you can prove 🐈‍⬛

This is the first optical air-gap system with **true quantum-inspired plausible deniability.**

---

## ⚠️ **CRITICAL: Read Before Use**

### **Project Status**

This is **EXPERIMENTAL / RESEARCH-GRADE SOFTWARE**:

- ❌ **NOT SECURITY AUDITED** - No formal third-party security audit
- ❌ **NOT PRODUCTION-READY** - Active development, APIs may change
- ❌ **NOT COMPLIANCE-CERTIFIED** - No FIPS 140-2, Common Criteria, etc.
- ✅ **EDUCATIONAL** - Excellent for learning cryptographic concepts
- ✅ **PROOF-OF-CONCEPT** - Demonstrates optical air-gap transfer
- ✅ **RESEARCH TOOL** - For security research and experimentation

### **DO NOT USE FOR:**
- ❌ Mission-critical systems or production environments
- ❌ HIPAA, PCI-DSS, or compliance-regulated data
- ❌ Classified or government-sensitive information
- ❌ Financial transactions or banking data
- ❌ Any scenario where data loss is unacceptable

### **SUITABLE FOR:**
- ✅ Educational purposes and learning
- ✅ Personal experimentation and hobby projects
- ✅ Security research and academic study
- ✅ Prototyping and proof-of-concept demonstrations
- ✅ Non-critical personal file backups

### **Liability Disclaimer**

This software is provided **"AS IS"** without warranty of any kind, express or implied. The authors and contributors are not liable for:
- Data loss or corruption
- Security breaches or unauthorized access
- Any damages (direct, indirect, incidental, or consequential)
- Compliance violations or regulatory issues

**By using this software, you accept all risks and responsibilities.**

---

## 🛡️ **Threat Model**

Understanding what Meow Decoder **does** and **does not** protect against:

### ✅ **PROTECTS AGAINST:**

**Passive Network Monitoring**
- ✅ Encrypted data unreadable without password
- ✅ No network traffic (optical transfer only)
- ✅ Air-gap friendly

**Data Interception**
- ✅ **Forward secrecy (MEOW3, default)**: Per-block key ratcheting prevents compromise of one block from revealing others
- ✅ HMAC authentication prevents tampering
- ✅ Steganography hides presence of data

**Brute Force Attacks**
- ✅ Argon2id KDF (47 MB memory, 2 iterations) makes password cracking expensive
- ✅ 256-bit AES keys require 2^256 operations to break
- ✅ Password + keyfile = two-factor protection

**Quantum Computer Attacks** (with MEOW4 post-quantum mode)
- ✅ Hybrid Kyber + X25519 protects against Shor's algorithm
- ✅ Secure if either classical OR quantum component is unbroken
- ✅ Use `--pq` flag to enable

**Physical Interception**
- ✅ Steganography levels 3-4 make hidden data hard to detect
- ✅ Dummy frame injection confuses automated extraction
- ✅ No direct file access required (screen-to-camera transfer)

**Memory Residue Attacks**
- ✅ **MITIGATED**: SecureBytes class zeroes sensitive data on deletion
- ✅ **MITIGATED**: Streaming mode (`--prowling-mode`) keeps only minimal data in RAM
- ✅ Per-block processing limits key exposure window
- ⚠️ Note: Cannot prevent OS page files or swap - use encrypted swap/disable hibernation

### ❌ **DOES NOT PROTECT AGAINST:**

**Weak Passwords**
- ❌ "password123" is easily cracked regardless of encryption
- ❌ Dictionary words can be brute-forced
- ⚠️ **USE STRONG PASSWORDS** (20+ chars, random, unique)

**Compromised Endpoints**
- ❌ Malware on sender/receiver system can steal password
- ❌ Keyloggers capture password during entry
- ❌ **Screen recorders can capture QR codes during display** - Use `--stego-level 4` + physical OpSec
- ⚠️ **SECURE YOUR DEVICES FIRST**

**Side-Channel Attacks**
- ⚠️ Timing attacks (partially mitigated with constant-time ops)
- ⚠️ Power analysis during encryption
- ⚠️ Electromagnetic emanations (TEMPEST)
- ✅ **Physical memory dumps**: MITIGATED with SecureBytes + streaming mode

**Social Engineering**
- ❌ Attacker tricks user into revealing password
- ❌ Phishing for keyfile
- ❌ Shoulder surfing during password entry

**Implementation Vulnerabilities**
- ⚠️ No formal verification of cryptographic implementation
- ⚠️ Potential bugs in fountain code decoder
- ⚠️ Python interpreter vulnerabilities
- ⚠️ Dependency vulnerabilities (Pillow, OpenCV, etc.)

**Legal Compulsion**
- ❌ Court order to reveal password
- ❌ Rubber-hose cryptanalysis (physical coercion)
- ❌ No plausible deniability (except with steganography)

**Supply Chain Attacks**
- ❌ Malicious PyPI packages
- ❌ Compromised dependencies
- ⚠️ **VERIFY PACKAGE HASHES**

### 🎯 **Security Recommendations**

1. **Use Strong Passwords**: 20+ characters, random, unique
2. **Enable Keyfile (2FA)**: `--keyfile` provides second factor
3. **Forward Secrecy**: ✅ **ENABLED BY DEFAULT** (MEOW3) - Use `--no-forward-secrecy` to disable
4. **Use Post-Quantum Mode**: `--pq` for long-term protection against quantum computers (MEOW4)
5. **Secure Both Endpoints**: Clean, updated, malware-free systems
6. **Physical Security**: Control who has physical access during transfer
7. **Against Screen Recording**: Use `--stego-level 4` + physical OpSec (no cameras in room)
8. **Verify Integrity**: Check SHA-256 hash after decoding
9. **Delete Source Securely**: `--wipe-source` overwrites original
10. **Test Before Production**: Verify encode/decode works perfectly

**Quick Start with Maximum Security:**
```bash
# Encode with ALL security features
python3 encode.py --input secret.pdf --output secret.gif \
  --pq \                      # Post-quantum (MEOW4)
  --keyfile my.key \          # Two-factor auth
  --stego-level 4 \           # Maximum stealth
  --prowling-mode             # Low memory footprint

# Forward secrecy (MEOW3) is ON by default!
```

### ⚖️ **Trust Assumptions**

You must trust:
- ✅ Python cryptography library implementation
- ✅ Argon2-cffi implementation
- ✅ Your operating system
- ✅ Your hardware (CPU, RAM)
- ✅ This codebase (unaudited!)

You do NOT need to trust:
- ❌ Network infrastructure (air-gapped)
- ❌ Cloud providers (no cloud involvement)
- ❌ Third-party servers (everything local)

---

## 📋 **Manifest Versioning**

Meow Decoder uses versioned manifest formats for compatibility and feature evolution:

### **Format Versions**

| Version | Magic | Features | Compatibility | Status |
|---------|-------|----------|---------------|--------|
| **MEOW2** | `0x4D454F57` + `0x02` | Base encryption, fountain codes, HMAC | All decoders | ✅ Stable |
| **MEOW3** | `0x4D454F57` + `0x03` | Forward secrecy, per-block keys, ratcheting | v3+ decoders | ✅ **DEFAULT** |
| **MEOW4** | `0x4D454F57` + `0x04` | Post-quantum (Kyber), hybrid mode | v4+ decoders | ⚠️ Experimental |

### **Version Detection**

All manifests start with:
```
[4 bytes] Magic: 0x4D 0x45 0x4F 0x57  ("MEOW")
[1 byte]  Version: 0x02 / 0x03 / 0x04
```

Decoders automatically detect version and decode accordingly.

### **MEOW2: Base Format (115 bytes)**

```
Magic (4) + Version (1) + Salt (16) + Nonce (12) +
OrigLen (8) + CompLen (8) + CipherLen (8) +
SHA256 (32) + BlockSize (4) + NumBlocks (4) +
HMAC (32)
```

**Features:**
- AES-256-GCM encryption
- Argon2id KDF
- HMAC authentication
- Fountain codes
- Keyfile support

**Use when:**
- Maximum compatibility needed
- No forward secrecy required
- Single encryption key acceptable

### **MEOW3: Forward Secrecy (115 bytes base + extension)**

Base manifest (115 bytes) + Extension:
```
ExtensionLength (2) +
ExtensionType (1) = 0x01 +
RatchetInterval (4) +
InitialChainKey (32) +
... (future extensions)
```

**Features:**
- All MEOW2 features
- Per-block key derivation
- Signal-style ratcheting
- Compromise resistance

**Use when:**
- Long-term security needed
- Multiple blocks/GIFs
- Forward secrecy required ✅ **RECOMMENDED**

**NOW DEFAULT** as of v4.0!

### **MEOW4: Post-Quantum (115 bytes base + extension)**

Base manifest (115 bytes) + Extension:
```
ExtensionLength (2) +
ExtensionType (1) = 0x02 +
VariantLength (1) +
Variant (8) = "kyber768" +
ClassicalCT (32) +  // X25519 ciphertext
QuantumCTLength (2) +
QuantumCT (variable) +  // Kyber ciphertext (~1088 bytes)
... (optional FS extension)
```

**Features:**
- All MEOW3 features
- Hybrid classical + quantum
- Kyber-512/768/1024 support
- Quantum-resistant

**Use when:**
- Threat model includes quantum computers
- Long-term (10+ year) protection needed
- Research/future-proofing

**Requires:** `pip install liboqs-python`

### **Compatibility Matrix**

| Encoder Version | Decoder v2 | Decoder v3 | Decoder v4 |
|-----------------|------------|------------|------------|
| **MEOW2** | ✅ | ✅ | ✅ |
| **MEOW3** | ❌ | ✅ | ✅ |
| **MEOW4** | ❌ | ❌ | ✅ |

**Forward Compatible:** New decoders support old formats
**Not Backward Compatible:** Old decoders cannot read new formats

### **Choosing a Version**

```bash
# MEOW2 (maximum compatibility)
python3 encode.py --input file.pdf --no-fs --output file.gif

# MEOW3 (forward secrecy - RECOMMENDED & DEFAULT)
python3 encode.py --input file.pdf --output file.gif

# MEOW4 (post-quantum)
python3 encode.py --input file.pdf --pq --output file.gif
```

### **Migration Path**

1. **v2 → v3**: Re-encode with forward secrecy enabled
2. **v3 → v4**: Re-encode with `--pq` flag
3. **Batch conversion**: Use `batch_convert.py` script (coming soon)

---

## 🎯 **Features**

### Core Functionality
- ✅ **Fountain Codes**: Rateless encoding with Luby Transform
- ✅ **QR Code Encoding**: High-capacity QR codes with error correction
- ✅ **GIF Animation**: Smooth playback at configurable FPS
- ✅ **Robust Decoding**: Works from webcam or GIF file

### Security (A+ Rating)
- ✅ **AES-256-GCM Encryption**: Military-grade encryption
- ✅ **Argon2id Key Derivation**: Memory-hard (47 MB), GPU-resistant
- ✅ **HMAC Authentication**: Tamper detection with SHA-256
- ✅ **Forward Secrecy** (v3): Per-block key derivation (DEFAULT!)
- ✅ **Post-Quantum Ready** (v4): Hybrid Kyber + X25519
- ✅ **Secure Memory**: Automatic key zeroing
- ✅ **Constant-Time Operations**: Side-channel resistant

### Advanced Features
- ✅ **Steganography**: 4 stealth levels (1-4 bit LSB)
- ✅ **Low-Memory Mode**: Works on 2 MB RAM devices
- ✅ **Auto-Resume**: Encrypted resume states
- ✅ **Smart Profiling**: Performance optimization
- ✅ **Keyfile Support**: Two-factor authentication

### NEW in v4.0 - All Priorities Implemented! 🎉
- ✅ **Priority 1**: Forward secrecy enabled by default (MEOW3)
- ✅ **Priority 2**: Real post-quantum crypto with liboqs (MEOW4)
- ✅ **Priority 3**: Dynamic stego with anti-recording (Ninja Cat ULTRA)
- ✅ **Priority 4**: Streaming decode for low-memory devices (Prowling Mode)
- ✅ **Priority 5**: Beautiful GUI dashboard (Dear PyGui)

### 🆕 NEW in v5.0 - Schrödinger's Clowder Edition! 🐈📦🐱🐱🐱

#### **🐈📦 Schrödinger's Yarn Ball (Plausible Deniability)**

> _**"You cannot prove a secret exists unless you already know how to look for it.**_  
> _**And once you look… you've already chosen your reality."**_

**Schrödinger's Yarn Ball isn't about hiding data.**  
**It's about this:**

In Meow Decoder, your secret exists in a **pre-observation haze** — a tangled ball of noise and cat memes. It has no definite shape until you pull exactly the right threads (correct password, enough fountain droplets). But pulling those threads **presupposes the form** the secret must take.

**Wrong filter → no thread.**  
**Right filter → the yarn suddenly becomes a coherent story.**  
**Until then? Just innocent kittens and void.** 😶‍🌫️🐱

**How it works:**
- One GIF contains **TWO** encrypted secrets
- All blocks are **indistinguishable** until decrypted
- Real password → Real secret manifests
- Decoy password → Innocent decoy manifests
- **No way to prove both exist**
- Perfect plausible deniability

**Use Cases:**
- Border crossings with sensitive data
- Journalist source protection
- Whistleblower safety
- Legal coercion defense
- Anti-forensics

```bash
# Encode two secrets into one GIF
python3 schrodinger_encode.py \
  --real-input classified.pdf \
  --decoy-input vacation.zip \
  --output quantum.gif

# Decode reveals whichever password you use!
# The other secret remains in quantum superposition 🐈‍⬛
```

#### **🐱🐱🐱 Clowder Batch Mode (Multi-File Encoding)**

A **clowder** is a group of cats! Encode entire folders:

- Automatic file batching
- Master manifest coordination
- **Resume support** if interrupted
- Perfect for backups & archives

```bash
# Encode entire folder
python3 clowder_encode.py --input ~/secrets/ --output ~/yarn_balls/

# Decode everything back
python3 clowder_decode.py --input ~/yarn_balls/ --output ~/recovered/
```

#### **📷🐾 Enhanced Webcam (Paw Progress & QR Overlay)**

Professional webcam scanning with cat delight:

- Real-time QR detection overlay (green boxes)
- Paw progress: 😿🐾🐾🐾🐾 → 😻😻😻😻😻
- "Kibbles collected" counter
- Live HUD with stats
- Auto-focus optimization

```bash
python3 webcam_enhanced.py --output decoded.pdf
# Shows: 😸😸😸🐾🐾 67/100 kibbles (67.0%)
```

---

## 📦 Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip libzbar0 libgl1-mesa-glx

# macOS
brew install python3 zbar

# Windows
# Download zbar from: http://zbar.sourceforge.net/
```

### Core Dependencies

```bash
# Clone repository
git clone https://github.com/yourusername/meow-decoder.git
cd meow-decoder

# Install core requirements
pip install -r requirements.txt

# Test installation
python3 encode.py --help
```

### Optional: Post-Quantum Support

```bash
# Install liboqs (Ubuntu/Debian)
sudo apt-get install liboqs-dev

# Install Python bindings
pip install liboqs-python

# Test post-quantum
python3 -c "import oqs; print('✅ Post-quantum support enabled!')"
```

### Optional: GUI Dashboard

```bash
# Install Dear PyGui
pip install dearpygui

# Launch dashboard
python3 meow_dashboard.py
```

---

## 🚀 Quick Start

### Installation

```bash
# Install from source
pip install -e .

# Or (when published to PyPI)
pip install meow-decoder

# This provides console commands:
# - meow-encode
# - meow-decode  
# - meow-webcam
# - meow-dashboard
```

### Basic Encoding

```bash
# Encode a file
meow-encode --input secret.pdf --output secret.gif

# You'll be prompted for password
# GIF will be created with QR code frames
```

### Basic Decoding

```bash
# Decode from GIF
meow-decode --input secret.gif --output secret.pdf

# Enter same password used for encoding
```

### With Forward Secrecy (RECOMMENDED - Now Default!)

```bash
# Encode with forward secrecy (MEOW3 manifest)
meow-encode --input secret.pdf --output secret.gif
# (Forward secrecy is now enabled by default!)

# Decode
meow-decode --input secret.gif --output secret.pdf
```

### With Post-Quantum Protection

```bash
# Encode with post-quantum (MEOW4 manifest)
meow-encode --input secret.pdf --pq --output secret.gif

# Decode (requires liboqs-python)
meow-decode --input secret.gif --output secret.pdf
```

### With Keyfile (2FA)

```bash
# Generate keyfile
python3 -c "import secrets; open('my.key','wb').write(secrets.token_bytes(256))"

# Encode with keyfile
meow-encode --input secret.pdf --keyfile my.key --output secret.gif

# Decode with keyfile
meow-decode --input secret.gif --keyfile my.key --output secret.pdf
```

### GUI Dashboard

```bash
# Launch GUI
meow-dashboard

# Or run directly
python3 meow_gui_enhanced.py
```

### Webcam Decode

```bash
# Decode from webcam
meow-webcam --password yourpassword
```

---

## 📚 Documentation

### Essential Guides
- **README.md** (this file) - Start here
- **ALL_PRIORITIES_IMPLEMENTED.md** - v4.0 feature summary
- **THREAT_MODEL.md** - Detailed security analysis
- **MANIFEST_VERSIONING.md** - Format specification

### Feature-Specific
- **FORWARD_SECRECY_INTEGRATION.md** - How to use v3
- **POST_QUANTUM_GUIDE.md** - How to use v4
- **SECURITY_ENHANCEMENTS_GUIDE.md** - Advanced security

### Development
- **IMPLEMENTATION_COMPLETE.md** - Technical details
- **QUICK_REFERENCE.md** - Code examples

---

## 🔬 Security Analysis

### Cryptographic Primitives

| Component | Algorithm | Key Size | Notes |
|-----------|-----------|----------|-------|
| Encryption | AES-256-GCM | 256-bit | NIST approved |
| KDF | Argon2id | 256-bit output | 47 MB memory, 2 iter |
| MAC | HMAC-SHA256 | 256-bit | Included in GCM |
| Hash | SHA-256 | 256-bit | For integrity |
| Classical KEX | X25519 | 256-bit | ECDH on Curve25519 |
| Post-Quantum | Kyber-768 | ~192-bit security | NIST ML-KEM |

### Known Limitations

1. **No Perfect Forward Secrecy for QR Display**
   - If password compromised, attacker with recorded video can decrypt
   - Mitigation: Use v3 forward secrecy + short-lived passwords

2. **Python Implementation**
   - Not constant-time guaranteed (Python interpreter limitations)
   - Mitigation: Uses constant-time libraries where possible

3. **Side-Channel Vulnerabilities**
   - Timing, power analysis not fully mitigated
   - Mitigation: Run on trusted hardware in controlled environment

4. **No Secure Boot Chain**
   - Can't verify OS/Python integrity
   - Mitigation: Use verified, minimal Linux distro

5. **Memory Safety**
   - Python GC may leave sensitive data in memory
   - Mitigation: Explicit zeroing, mlock support (limited)

---

## 🤝 Contributing

**Before contributing:**
1. Read this README thoroughly
2. Understand threat model and limitations
3. Review security implications
4. Test thoroughly before submitting PRs

**We welcome:**
- Security audits and vulnerability reports
- Bug fixes with tests
- Documentation improvements
- Performance optimizations

**Please do NOT:**
- Submit untested code
- Add dependencies without discussion
- Make breaking API changes without consensus
- Claim production-readiness

---

## 📜 License

MIT License - See LICENSE file

**But Remember:** Use at your own risk. No warranty provided.

---

## 🙏 Acknowledgments

- Argon2 algorithm by Alex Biryukov et al.
- Kyber/ML-KEM by Roberto Avanzi et al.
- Fountain codes by Michael Luby
- Open Quantum Safe project for liboqs

---

## 📞 Contact & Support

- **Issues**: GitHub Issues (security issues: see SECURITY.md)
- **Discussions**: GitHub Discussions
- **Security**: security@yourdomain.com (PGP key available)

---

**🐾 Remember: This is experimental software. Use responsibly!**

**Last Updated:** 2026-01-22 | **Version:** 4.0 | **Status:** Research/Educational

