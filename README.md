# 🐱 Meow Decoder

<p align="center">
  <img src="assets/meow-decoder-logo.png" alt="Meow Decoder Logo" width="600">
</p>

<p align="center">
  <strong>Smuggle bytes through the air — Security‑focused QR code encryption</strong>
</p>

<p align="center">
  <a href="https://github.com/systemslibrarian/meow-decoder/actions/workflows/security-ci.yml">
    <img src="https://github.com/systemslibrarian/meow-decoder/actions/workflows/security-ci.yml/badge.svg" alt="Security CI">
  </a>
  <a href="https://github.com/systemslibrarian/meow-decoder/actions/workflows/codeql.yml">
    <img src="https://github.com/systemslibrarian/meow-decoder/actions/workflows/codeql.yml/badge.svg" alt="CodeQL">
  </a>
  <a href="https://codecov.io/gh/systemslibrarian/meow-decoder">
    <img src="https://codecov.io/gh/systemslibrarian/meow-decoder/branch/main/graph/badge.svg" alt="codecov">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License">
  </a>
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+">
</p>

---

## 🎬 Demo (How It Works)

<p align="center">
  <img src="assets/demo.gif" alt="Meow Decoder demo: Encode → Transmit → Decode" width="750">
</p>

This demo shows the **clear mechanics** of Meow Decoder.  
Each frame of the animated GIF contains encrypted payload bytes encoded into QR frames.

This version is intentionally explicit — it teaches and reassures.

---

## 🐈 Camouflage Mode (Optional)

<p align="center">
  <img src="assets/demo_camouflage.gif" alt="Camouflaged payload disguised as a cat GIF" width="750">
</p>

Same encrypted‑payload concept, but **visually disguised** as a harmless looping cat animation.

Humans see a normal GIF.  
The decoder extracts structured data from each frame.

Use the clear demo above to learn.  
This one exists for **plausible deniability and personality**.

---

## 🚀 What Is Meow Decoder?

**Meow Decoder** transforms sensitive files into animated GIFs containing QR‑encoded frames, enabling secure **air‑gapped data transfer**.

It is designed for environments where:
- Networks are untrusted or unavailable
- Removable media is restricted
- Only cameras and screens can cross boundaries

---

## ✨ Key Features

- 🔒 **Strong Encryption** — AES‑256‑GCM with Argon2id key derivation  
- 📱 **Air‑Gap Friendly** — Transfer data using only screens and cameras  
- 🛡️ **Forward Secrecy (Optional)** — X25519 ephemeral key exchange  
- 🐈‍⬛ **Schrödinger Mode** — Dual‑secret plausible deniability  
- 📊 **Error Resilience** — Fountain codes tolerate dropped frames  
- ✅ **CI‑Enforced Quality** — Security tests on every commit  

---

## 📦 Quick Start

### Install

```bash
pip install meow-decoder
```

Or from source:

```bash
git clone https://github.com/systemslibrarian/meow-decoder.git
cd meow-decoder
pip install -e .
```

### Encrypt

```bash
meow-encode -i secret.txt -o payload.gif -p "passphrase"
```

### Decrypt

```bash
meow-decode-gif -i payload.gif -o recovered.txt -p "passphrase"
```

---

## 📱 Phone‑Based Transfer Model

Meow Decoder **does not require a mobile app**.

### Workflow

1. Display the animated GIF on any screen  
2. Record the looping animation with a phone (video or burst photos)  
3. Transfer the recording to a computer  
4. Decode on the computer using the passphrase  

The phone is treated as an **untrusted optical sensor**.  
All cryptography and verification occur on the trusted machine.

---

## 🎯 Security Properties

| Property | Status |
|-------|--------|
| Authenticated Encryption | AES‑256‑GCM |
| Key Derivation | Argon2id |
| Tamper Detection | Frame + manifest MACs |
| Forward Secrecy | Optional (X25519) |
| Error Recovery | Fountain codes |
| Security CI | Enforced |

See:
- [Security Policy](SECURITY.md)
- [Threat Model](docs/THREAT_MODEL.md)

---

## 🏗️ Architecture (High‑Level)

```
File → Encrypt → Fountain Encode → QR Frames → Animated GIF
                                   ↑
                              Camera Capture
```

Detailed internals:
- [Architecture](docs/ARCHITECTURE.md)

---

## 🧪 Development

```bash
pytest tests/
pytest tests/test_security.py tests/test_adversarial.py
```

CI runs on Python 3.10–3.12 with CodeQL and security checks enabled.

---

## 📖 Documentation

- [Usage Guide](docs/USAGE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Schrödinger Mode](docs/SCHRODINGER.md)
- [Stability Tiers](docs/STABILITY_TIERS.md)

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

<p align="center">
  <strong>Built for air‑gapped, hostile, and zero‑trust environments.</strong>
</p>
