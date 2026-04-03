# 🐾 Meow Decoder

<p align="center">
  <img src="assets/meow-decoder-logo.png" alt="Meow Decoder Logo" width="200"/>
</p>

---

## ▶️ Demo

https://www.meowdecoder.com

---

<p align="center">
  <b>Secure Air-Gapped Data Transfer via Animated QR Frames</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-active--development-orange"/>
  <img src="https://img.shields.io/badge/security-AEAD%20%2B%20Argon2id-blue"/>
  <img src="https://img.shields.io/badge/license-MIT-green"/>
</p>

---

## 🚀 Overview

**Meow Decoder is a cryptographic system for transferring data across air gaps using animated QR code frames — where the camera is treated as an untrusted optical channel and all security guarantees are enforced at the endpoints.**

> Designed with explicit threat modeling, AEAD encryption, and fail-closed parsing — not as a demo, but as a security-first protocol.

---

## 🧠 Why This Matters

Air-gapped environments are common in high-security systems, but data transfer across them is often:

- Manual  
- Error-prone  
- Insecure (USB risks, human handling)  

**Meow Decoder provides a structured, verifiable, and cryptographically sound method of transferring data across air gaps using only visual transmission.**

---

## 🔑 Core Concept

- Encrypt data locally
- Split into structured frames
- Encode frames as QR codes
- Transmit visually
- Reconstruct and verify securely

**The camera is treated as hostile/untrusted.  
All integrity and authenticity guarantees are enforced cryptographically.**

---

## 🔐 Security Model

### Threat Assumptions
- Capture device may be compromised
- Frames may be:
  - Dropped
  - Reordered
  - Tampered with
  - Observed

### Security Guarantees

- **Confidentiality** → AES-256-GCM  
- **Integrity** → AEAD authentication tags  
- **Replay Protection** → Frame sequencing  
- **Tamper Detection** → Fail-closed decoding  
- **Key Derivation** → Argon2id (memory-hard)  

---

## 🧪 Cryptographic Design

| Component        | Implementation            |
|-----------------|--------------------------|
| Encryption      | AES-256-GCM              |
| Key Derivation  | Argon2id                 |
| Encoding        | Binary → QR frames       |
| Protocol        | Versioned byte spec      |
| Parsing         | Fail-closed validation   |

---

## ⚙️ How It Works

### 1. Encode
- Data encrypted using AEAD
- Split into frames
- Each frame includes:
  - Sequence number
  - Payload
  - Authentication tag

### 2. Transmit
- Frames rendered as animated QR codes
- Displayed sequentially

### 3. Capture
- Receiver scans frames via camera
- Frames buffered and ordered

### 4. Decode
- Frames validated
- Authentication verified
- Data decrypted only if all checks pass

---

## 🛡️ Design Principles

- **Fail Closed** → reject on any inconsistency  
- **Explicit Protocol** → byte-level specification  
- **Untrusted Channel** → camera is not trusted  
- **Deterministic Behavior** → no silent recovery  
- **Security First** → always over convenience  

---

## 📸 Architecture

```
[ Secure Sender ]
        │
        ▼
  Encrypted Frames
        │
        ▼
  QR Code Sequence
        │
        ▼
[ Untrusted Camera ]
        │
        ▼
[ Secure Receiver ]
        │
        ▼
 Validation → Decryption → Output
```



## 📦 Example Usage

```bash
meow encode --input secret.txt --output frames/
meow decode --input frames/ --output recovered.txt
```

---

## ⚠️ Status

**Active Development — Security Hardening Phase**

---

## 🙋‍♂️ Author

Paul Clark  
Systems Librarian · AI Builder · Security-Focused Engineer  

---

## 📜 License

MIT
