# 🐱 Meow Decoder

<p align="center">
  <img src="assets/meow-decoder-logo.png" alt="Meow Decoder Logo" width="600">
</p>

<p align="center">
  <strong>Smuggle bytes through the air — Security-focused QR code encryption</strong>
</p>

<p align="center">
  <a href="https://github.com/systemslibrarian/meow-decoder/actions/workflows/security-ci.yml">
    <img src="https://github.com/systemslibrarian/meow-decoder/actions/workflows/security-ci.yml/badge.svg" alt="Security CI">
  </a>
  <a href="https://github.com/systemslibrarian/meow-decoder/actions/workflows/codeql.yml">
    <img src="https://github.com/systemslibrarian/meow-decoder/actions/workflows/codeql.yml/badge.svg" alt="CodeQL Security Scan">
  </a>
  <a href="https://codecov.io/gh/systemslibrarian/meow-decoder">
    <img src="https://codecov.io/gh/systemslibrarian/meow-decoder/branch/main/graph/badge.svg" alt="codecov">
  </a>
  <a href="https://github.com/systemslibrarian/meow-decoder/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT">
  </a>
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+">
  </a>
</p>

## 🎬 Demo

<p align="center">
  <img src="assets/demo.gif" alt="Meow Decoder demo: Encode → Transmit → Decode" width="750">
</p>

The GIF above is a preview. In real use, the encoder generates an **animated QR GIF** where **each frame carries encrypted payload bytes**.

---

## 🚀 What is Meow Decoder?

**Meow Decoder** transforms sensitive files into animated GIFs containing QR codes, enabling secure air-gapped data transfer.  
It is designed for environments where **networks are untrusted or unavailable**.

### ✨ Key Features

- 🔒 **Strong Encryption**: AES-256-GCM with Argon2id key derivation
- 📱 **Air-Gap Friendly**: Transfer data via QR codes using any camera
- 🛡️ **Forward Secrecy (Optional)**: X25519 ephemeral key exchange
- 🐈‍⬛ **Schrödinger Mode**: Dual-secret plausible deniability
- 📊 **Error Resilient**: Fountain codes tolerate dropped or damaged frames
- ✅ **CI-Enforced Quality**: Security and regression tests on every commit

---

## 📦 Quick Start

### Installation

```bash
pip install meow-decoder
```

Or from source:

```bash
git clone https://github.com/systemslibrarian/meow-decoder.git
cd meow-decoder
pip install -e .
```

### Basic Usage

**Encrypt a file**
```bash
meow-encode -i secret.txt -o animated.gif -p "my-secure-password"
```

**Decrypt a file**
```bash
meow-decode-gif -i animated.gif -o recovered.txt -p "my-secure-password"
```

---

## 📱 Phone-Based Transfer Model

Meow Decoder intentionally **does not require a mobile app**.

### Workflow

1. **Display** the animated QR GIF on any screen
2. **Record** the looping animation with a phone camera (video or burst photos)
3. **Transfer** the recording to a computer
4. **Decode** on the computer using the passphrase

This design treats the phone as an **untrusted optical sensor**, while cryptography and decoding occur on a trusted machine.

---

## 🎯 Security Properties

| Property | Status |
|--------|--------|
| Authenticated Encryption | ✅ AES-256-GCM |
| Key Derivation | ✅ Argon2id |
| Tamper Detection | ✅ Frame & manifest MACs |
| Forward Secrecy | ✅ Optional (X25519) |
| Error Recovery | ✅ Fountain codes |
| CI Security Tests | ✅ Enforced |

For details, see:
- [Security Policy](SECURITY.md)
- [Threat Model](docs/THREAT_MODEL.md)

---

## 🏗️ Architecture (High-Level)

```
File → Encrypt → Fountain Encode → QR Frames → Animated GIF
                                   ↑
                              Camera Capture
```

A detailed walkthrough is available in:
- [Architecture](docs/ARCHITECTURE.md)

---

## 🧪 Development

```bash
# Run tests
pytest tests/

# Security-focused tests
pytest tests/test_security.py tests/test_adversarial.py
```

CI runs on Python 3.10–3.12 with CodeQL and security checks enabled.

---

## 📖 Documentation

- [Usage Guide](docs/USAGE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Schrödinger Mode](docs/SCHRODINGER.md)

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

<p align="center">
  <strong>Built for air-gapped, hostile, or zero-trust environments.</strong>
</p>
