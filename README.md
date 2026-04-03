# 🐱 Meow Decoder

<p align="center">
  <img src="assets/meow-decoder-logo.png" alt="Meow Decoder Logo" width="600">
</p>

<p align="center">
  <strong>Secure air-gapped data transfer via animated QR frames — with real cryptography, explicit threat modeling, and adversarial resilience.</strong>
</p>

<p align="center">
  <em>Meow Decoder lets you securely transfer files between air-gapped computers using only a phone camera as a dumb optical bridge — animated QR codes carry AES-256-GCM encrypted data with forward secrecy, post-quantum protection, and experimental deniability features.</em>
</p>

---

## 🧠 At a Glance

- AES-256-GCM + Argon2id (512 MiB, 20 iterations)  
- Forward Secrecy (X25519, default)  
- Post-Quantum Hybrid (ML-KEM-768 / 1024)  
- Fountain Codes (~33% frame loss tolerance)  
- Rust cryptographic core (constant-time, zeroize)  
- Formal verification + fuzz testing  

---

## ⚠️ Who This Is For (And Who It Isn't)

| ✅ This IS for you if... | ❌ This is NOT for you if... |
|--------------------------|------------------------------|
| You're a developer/researcher | You want a consumer mobile app |
| You need air-gapped file transfer | You want one-tap phone scanning |
| You understand command-line tools | You need plug-and-play simplicity |
| You want to audit the crypto yourself | You need production enterprise support |

**Honest disclaimer:** This is a **developer/research tool**. It requires Python, command-line comfort, and understanding of what you're doing.

---

## ⏱️ How It Works (60 Seconds)

Sender → Encode → QR Frames → Camera → Decode → File restored

The phone is just a dumb optical sensor. All crypto happens on trusted computers.

---

## ✨ Key Features

- 🔒 AES-256-GCM authenticated encryption  
- 🔑 Argon2id memory-hard key derivation  
- 🛡️ Forward secrecy + post-quantum hybrid  
- 📊 Fountain codes for resilience  
- 🔐 Duress + deniability modes  
- 🦀 Rust-backed cryptography  

---

## ▶️ Demo

http://www.meowdecoder.com/

---

## 🚀 Quick Start

```bash
pip install meow-decoder

meow-encode -i secret.pdf -o secret.gif -p "password"
meow-decode-gif -i captured.mp4 -o recovered.pdf -p "password"
```

---

## 🔐 Security Philosophy

- Fail closed  
- Assume hostile capture channel  
- No silent recovery  
- Cryptography over convenience  

---

## 📄 License

See LICENSE file.
