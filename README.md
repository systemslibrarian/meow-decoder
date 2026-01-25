# 🐱 Meow Decoder

# ⚠️ EXPERIMENTAL PROTOTYPE – NO INDEPENDENT AUDIT – RESEARCH/TESTING USE ONLY ⚠️

> **Do NOT transfer real sensitive data. Potential side-channels, bugs, or undiscovered issues exist.**
>
> **See [THREAT_MODEL.md](docs/THREAT_MODEL.md) and [SECURITY.md](SECURITY.md) for assumptions/limitations.**

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
    <img src="https://github.com/systemslibrarian/meow-decoder/actions/workflows/codeql.yml/badge.svg" alt="CodeQL">
  </a>
  <a href="https://codecov.io/gh/systemslibrarian/meow-decoder">
    <img src="https://codecov.io/gh/systemslibrarian/meow-decoder/branch/main/graph/badge.svg" alt="codecov">
  </a>
  <a href="https://github.com/systemslibrarian/meow-decoder/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License">
  </a>
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+">
  </a>
</p>

---

## ⚠️ Who This Is For (And Who It Isn't)

| ✅ This IS for you if... | ❌ This is NOT for you if... |
|--------------------------|------------------------------|
| You're a developer/researcher | You want a consumer mobile app |
| You need air-gapped file transfer | You want one-tap phone scanning |
| You understand command-line tools | You need plug-and-play simplicity |
| You want to audit the crypto yourself | You need production enterprise support |

**Honest disclaimer:** This is a **developer/research tool**, not a consumer app (yet). It requires Python, command-line comfort, and understanding of what you're doing. If you're looking for a polished mobile experience, check back later or contribute!

---

## ⏱️ How It Works (60 Seconds)

**The Problem:** You need to move a file between two computers that can't touch the network (air-gapped, hostile network, zero-trust).

**The Solution:** Turn the file into animated QR codes, display on screen, record with any camera, decode on the other side.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        MEOW DECODER FLOW                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   SENDER (Computer A)              RECEIVER (Computer B)            │
│   ══════════════════               ════════════════════             │
│                                                                     │
│   ┌──────────────┐                                                  │
│   │  secret.pdf  │                                                  │
│   └──────┬───────┘                                                  │
│          │                                                          │
│          ▼                                                          │
│   ┌──────────────┐                                                  │
│   │ meow-encode  │  ← Encrypt + fountain code + QR                  │
│   └──────┬───────┘                                                  │
│          │                                                          │
│          ▼                                                          │
│   ┌──────────────┐         📱 Phone Camera        ┌──────────────┐ │
│   │ Animated GIF │ ═══════════════════════════════▶│ Video File   │ │
│   │ (QR codes)   │    Record the screen!          │ (.mp4/.mov)  │ │
│   └──────────────┘                                └──────┬───────┘ │
│                                                          │          │
│                              Transfer video to Computer B│          │
│                                       (USB, email, etc.) │          │
│                                                          ▼          │
│                                                   ┌──────────────┐  │
│                                                   │ meow-decode  │  │
│                                                   └──────┬───────┘  │
│                                                          │          │
│                                                          ▼          │
│                                                   ┌──────────────┐  │
│                                                   │  secret.pdf  │  │
│                                                   │  (recovered) │  │
│                                                   └──────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**That's it.** The phone is just a dumb optical sensor. All crypto happens on trusted computers.

---

## 🔐 What This Protects / Doesn't Protect

### ✅ DOES Protect Against

| Threat | How |
|--------|-----|
| **Network eavesdropping** | Data never touches a network |
| **Man-in-the-middle** | Optical channel, no network routing |
| **Brute force attacks** | Argon2id (256 MiB, 10 iterations) |
| **Tampering/modification** | AES-GCM authentication + HMAC |
| **Future password compromise** | Forward secrecy (X25519 ephemeral keys) |
| **Coercion ("give me the password")** | Schrödinger mode (plausible deniability) |
| **Dropped/corrupted frames** | Fountain codes (33% loss tolerance) |
| **Quantum computers (future)** | Post-quantum crypto (ML-KEM-768, optional) |

### ❌ Does NOT Protect Against

| Threat | Why |
|--------|-----|
| **Shoulder surfing** | Someone watching your screen sees the GIF |
| **Compromised endpoint** | Malware on sender/receiver defeats everything |
| **Keyloggers** | Password stolen before encryption |
| **Physical coercion (torture)** | No crypto defeats rubber-hose cryptanalysis |
| **Screen recording malware** | Same as shoulder surfing, automated |
| **State-level adversaries** | No formal audit; use certified tools for classified data |

### 🎯 Adversary Model

| Adversary | Can Meow Decoder Stop Them? |
|-----------|------------------------------|
| Script kiddie | ✅ Yes, easily |
| Skilled hacker (network) | ✅ Yes (no network exposure) |
| Corporate IT snooping | ✅ Yes (optical bypasses monitoring) |
| Law enforcement (legal demand) | ⚠️ Maybe (Schrödinger mode helps) |
| Intelligence agency | ⚠️ Partial (endpoint risk) |
| NSA with full resources | ❌ Not designed for this |

**Bottom line:** Strong crypto, but endpoints and operational security are YOUR responsibility.

---

## 🎬 Demo

<p align="center">
  <img src="assets/demo.gif" alt="Meow Decoder demo: Encode → Transmit → Decode" width="750">
</p>

This demo shows the **explicit mechanics** of Meow Decoder.  
QR codes are intentionally visible so first-time users can clearly understand what is happening.

---

## 🚀 Quick Start (5 Minutes)

### 1. Install

```bash
pip install meow-decoder
```

Or from source:
```bash
git clone https://github.com/systemslibrarian/meow-decoder.git
cd meow-decoder
pip install -e .
```

### 2. Encode (Sender)

```bash
# Encrypt a file into animated QR GIF
meow-encode -i secret.pdf -o secret.gif -p "YourStrongPassword123"
```

### 3. Display & Record

```bash
# Open the GIF (it loops automatically)
open secret.gif  # macOS
xdg-open secret.gif  # Linux
start secret.gif  # Windows
```

**Record the screen with your phone camera for 10-15 seconds.**

### 4. Transfer Video

Move the video file to the receiving computer (USB, email, cloud - the video is encrypted garbage without the password).

### 5. Decode (Receiver)

```bash
# Decrypt from the video recording
meow-decode-gif -i captured_video.mp4 -o recovered.pdf -p "YourStrongPassword123"
```

**Done!** Your file is recovered with integrity verification.

---

## ⚡ Optional Constant-Time Rust Crypto Backend

For maximum security and performance, Meow Decoder supports a Rust-based cryptographic backend. This uses the `rust_crypto` module to provide constant-time implementations of critical primitives (AES-GCM, Argon2id, etc.) via PyO3.

### Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) installed (`rustup`)
- `maturin` build tool (`pip install maturin`)

### Build & Enable
```bash
# Build the Rust extension
cd rust_crypto
maturin develop --release
cd ..

# Enable via environment variable
export MEOW_CRYPTO_BACKEND=rust
meow-encode -i secret.pdf ...
```
(Legacy aliases `MEOW_RUST=1` or `MEOW_USE_RUST=1` also work)

You can verify it is active by checking the verbose output `meow-encode -v ...`.

See [rust_crypto/README.md](rust_crypto/README.md) for full details.

---

## 🔬 Fuzzing & Security Testing

This project uses **AFL++** (via `atheris`) for continuous fuzzing of critical components to detect crashes and edge cases.

### Fuzz Targets
- **Manifest Parsing**: Tests against malformed binary structures
- **Crypto Operations**: Tests error handling in key derivation/decryption
- **Fountain Codes**: Tests droplet parsing logic

### Running Fuzzers
```bash
# Example: Fuzz manifest parser
python3 fuzz/fuzz_manifest.py -runs=100000
```
See [fuzz/README.md](fuzz/README.md) for detailed instructions on corpus generation and running specific targets.

**Findings:** Initial fuzzing runs have identified no crashes or critical parsing vulnerabilities to date. Continued fuzzing is recommended for production assurance.

---

## 🐈 Camouflage Modes (Optional)

Want the GIF to look innocent instead of obvious QR codes?

### Photographic Cat Camouflage
<p align="center">
  <img src="assets/demo_camouflage_photo.gif" alt="Photographic cat camouflage demo" width="750">
</p>

Looks like a normal looping cat GIF. Data hidden in image texture.

### Logo-Eyes Carrier
<p align="center">
  <img src="assets/demo_logo_eyes.gif" alt="Logo-eyes carrier demo" width="750">
</p>

Branded animation where the eyes contain the data.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔒 **AES-256-GCM** | Military-grade authenticated encryption |
| 🔑 **Argon2id** | Memory-hard KDF (256 MiB, 10 iterations) |
| 📱 **Air-Gap Friendly** | Transfer via any camera, no network needed |
| 🛡️ **Forward Secrecy** | X25519 ephemeral keys (optional) |
| 🐈‍⬛ **Schrödinger Mode** | Dual-secret plausible deniability |
| 🔮 **Post-Quantum** | ML-KEM-768 hybrid (optional) |
| 📊 **Fountain Codes** | Tolerates 33% frame loss |
| 🔐 **Duress Mode** | Panic password triggers secure wipe |
| 🖥️ **Hardware Keys** | TPM/YubiKey support (optional) |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    ENCODING PIPELINE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  File → Compress → Encrypt → Fountain Code → QR Frames → GIF   │
│          (zlib)   (AES-GCM)  (Luby Transform)  (qrcode)  (PIL)  │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                    DECODING PIPELINE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  GIF/Video → Extract Frames → Read QR → Fountain Decode →      │
│              (PIL/OpenCV)    (pyzbar)   (Belief Prop)           │
│                                                                 │
│           → Decrypt → Decompress → Verify Hash → File          │
│             (AES-GCM)   (zlib)     (SHA-256)                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Crypto Stack:**
- **Encryption:** AES-256-GCM (authenticated)
- **Key Derivation:** Argon2id (256 MiB memory, 10 iterations)
- **Forward Secrecy:** X25519 ECDH (optional)
- **Post-Quantum:** ML-KEM-768 + X25519 hybrid (optional)
- **Integrity:** HMAC-SHA256 + per-frame MACs
- **Error Correction:** Luby Transform fountain codes

For full details: [Architecture Documentation](docs/ARCHITECTURE.md)

---

## 🎯 Security Properties

| Property | Implementation | Status |
|----------|----------------|--------|
| Authenticated Encryption | AES-256-GCM | ✅ |
| Memory-Hard KDF | Argon2id (256 MiB) | ✅ |
| Tamper Detection | GCM tags + HMAC + frame MACs | ✅ |
| Forward Secrecy | X25519 ephemeral keys | ✅ Optional |
| Post-Quantum | ML-KEM-768 hybrid | ✅ Optional |
| Plausible Deniability | Schrödinger dual-secret | ✅ Optional |
| Coercion Resistance | Duress passwords | ✅ Optional |
| Error Recovery | Fountain codes (33% loss OK) | ✅ |
| Security Tests | 125+ tests, CI-enforced | ✅ |

**Full threat model:** [THREAT_MODEL.md](docs/THREAT_MODEL.md)

---

## 📱 Phone-Based Transfer Model

Meow Decoder intentionally **does not require a mobile app**.

### Why?

1. **Phones are untrusted** — treat them as dumb optical sensors
2. **No app = no attack surface** — nothing to exploit on the phone
3. **Works with any camera** — phone, webcam, DSLR, whatever
4. **All crypto on trusted machines** — you control the endpoints

### Workflow

1. Display the animated GIF on any screen  
2. Record the looping animation with a phone camera  
3. Transfer the video/photos to a computer  
4. Decode on the computer using the passphrase  

---

## 🙏 Inspired By

Meow Decoder builds on ideas from these pioneering projects:

| Project | Description | What We Learned |
|---------|-------------|-----------------|
| [**TXQR**](https://github.com/divan/txqr) | Transfer via QR - Protocol for animated QR data transfer using fountain codes | Fountain code mechanics for error correction |
| [**BitFountain**](https://github.com/mguentner/bitfountain) | Experimental data transceiver using QR codes between devices | Camera-to-camera interaction concepts |
| [**QRExfil**](https://github.com/Shell-Company/QRExfil) | Convert binary files to QR GIFs for air-gapped exfiltration | Demonstrated DLP bypass risks via optical channels |
| [**QRFileTransfer**](https://github.com/LucaIaco/QRFileTransfer) | Cross-platform offline file transfer using only camera streams | Platform-agnostic optical transfer |

### How Meow Decoder Differs

While inspired by these projects, Meow Decoder adds critical security features:

- 🔐 **Authenticated Encryption** — AES-256-GCM with HMAC (not just encoding)
- 🔮 **Post-Quantum Ready** — ML-KEM-768 + Dilithium3 hybrid cryptography
- 🌊 **Loss-Tolerant** — Fountain codes reconstruct from any ~1.5× k frames
- 🛡️ **Threat Modeled** — Explicit adversarial analysis ([THREAT_MODEL.md](docs/THREAT_MODEL.md))
- ⚛️ **Plausible Deniability** — Schrödinger mode with dual-secret encoding
- 🔑 **Forward Secrecy** — X25519 ephemeral keys protect past messages

---

## � Optional Constant-Time Rust Crypto

For higher performance and better constant-time guarantees, you can enable the Rust cryptographic backend.

### Installation

```bash
# 1. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Install maturin
pip install maturin

# 3. Build and install the Rust module
cd rust_crypto
maturin develop --release
```

### Usage

The encoder/decoder will automatically detect `meow_crypto_rs` if installed.
You can force it (or disable it) via environment variable:

```bash
# Force Rust backend
export MEOW_CRYPTO_BACKEND=rust

# Force Python backend
export MEOW_CRYPTO_BACKEND=python
```

**Benchmarks (Typical):**
*   **Key Derivation (Argon2id):** Rust is ~30% faster
*   **Encryption (AES-GCM):** Rust is ~2x faster
*   **Security:** Rust backend uses the `subtle` crate for verified constant-time comparisons.

---

## 🔬 Fuzzing & Security Testing

We use AFL++ with Python bindings (atheris) to test robustness against malformed inputs.

### Running Fuzzers

1.  **Install Atheris:**
    ```bash
    pip install atheris
    ```

2.  **Run a Fuzzer:**
    ```bash
    # Fuzz manifest parsing logic
    python3 fuzz/fuzz_manifest.py

    # Fuzz crypto operations
    python3 fuzz/fuzz_crypto.py
    ```

**Findings:**
*   Initial fuzzing passes (24-hour run) found no crashes in the core parser logic.
*   Continuous fuzzing is recommended before major releases.

See [fuzz/README.md](fuzz/README.md) for details.

---

## �🧪 Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest tests/

# Run security tests specifically
pytest tests/test_security.py tests/test_adversarial.py

# Run with coverage
pytest --cov=meow_decoder tests/
```

CI runs on Python 3.10–3.12 with CodeQL and security scanning.

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](QUICKSTART.md) | 5-minute phone capture demo |
| [Usage Guide](docs/USAGE.md) | Detailed usage instructions |
| [Threat Model](docs/THREAT_MODEL.md) | Security analysis & limitations |
| [Architecture](docs/ARCHITECTURE.md) | Technical deep-dive |
| [Schrödinger Mode](docs/SCHRODINGER.md) | Plausible deniability |
| [Security Roadmap](docs/ROADMAP.md) | Future security enhancements |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |

---

## 🤝 Contributing

Contributions welcome! Especially:
- Security researchers (find vulnerabilities, get credit)
- UX designers (help make it more accessible)
- Mobile developers (native app would be great)
- Cryptographers (review our implementation)

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

<p align="center">
  <strong>Built for air-gapped, hostile, or zero-trust environments.</strong>
  <br>
  <em>🐱 "Trust no network. Trust the cat." 🐱</em>
</p>
