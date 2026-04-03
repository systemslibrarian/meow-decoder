# 🐾 Meow Decoder
### Secure Air-Gapped Data Transfer via Animated QR Frames

**Meow Decoder is a cryptographic system for transferring data across air gaps using animated QR code frames — where the camera is treated as an untrusted optical channel and all security guarantees are enforced at the endpoints.**

> Designed with explicit threat modeling, AEAD encryption, and fail-closed parsing — not as a demo, but as a security-first protocol.

---

## 🚀 Why This Matters

Air-gapped systems are widely used in high-security environments, but data transfer across them is often:
- Manual
- Error-prone
- Insecure (USB risks, human handling)

**Meow Decoder provides a structured, verifiable, and cryptographically sound method of transferring data across air gaps using only visual transmission.**

---

## 🧠 Core Idea

- Encode encrypted data into a sequence of QR frames
- Display frames on a sending device
- Capture frames via camera on receiving device
- Reconstruct and verify securely

**The camera is treated as hostile/untrusted.  
All integrity and authenticity guarantees are enforced cryptographically.**

---

## 🔐 Security Model

### Threat Assumptions
- Camera/device capturing frames may be compromised
- Frames may be:
  - Dropped
  - Reordered
  - Tampered with
  - Observed by adversaries

### Guarantees
- **Confidentiality** → AES-256-GCM encryption
- **Integrity** → Authenticated encryption (AEAD tags)
- **Replay Protection** → Frame sequencing + validation
- **Tamper Detection** → Fail-closed decoding
- **Key Derivation** → Argon2id (memory-hard KDF)

---

## 🧪 Cryptographic Design

| Component | Implementation |
|----------|----------------|
| Encryption | AES-256-GCM |
| Key Derivation | Argon2id |
| Frame Encoding | Structured binary → QR |
| Protocol | Versioned, byte-level spec |
| Parsing | Fail-closed (reject on any inconsistency) |

---

## ⚙️ How It Works

### 1. Encode
- Input data is encrypted using AEAD
- Data is split into framed chunks
- Each frame includes:
  - Sequence number
  - Payload
  - Authentication tag

### 2. Transmit
- Frames are rendered as animated QR codes
- Displayed sequentially

### 3. Capture
- Receiving device scans frames via camera
- Frames are buffered and ordered

### 4. Decode
- Frames are validated and reassembled
- Authentication is verified
- Data is decrypted only if all checks pass

---

## 🛡️ Design Principles

- **Fail Closed** — Any inconsistency results in rejection
- **Explicit Protocol** — Fully specified byte-level format
- **Untrusted Channel Model** — Camera is not trusted
- **Deterministic Behavior** — No silent recovery from errors
- **Security > Convenience** — Always

---

## 📸 Architecture Overview

```
[Secure Sender] → (QR Frames) → [Untrusted Camera] → [Secure Receiver]

Encryption + Framing                Capture + Validation + Decryption
```

---

## ▶️ Demo

https://www.meowdecoder.com

---

## 📦 Example Usage

```bash
# Encode data into QR frames
meow encode --input secret.txt --output frames/

# Decode captured frames
meow decode --input frames/ --output recovered.txt
```

---

## ⚠️ Status

**Active Development — Security Hardening Phase**

- Protocol defined and implemented
- Threat model documented
- Additional work:
  - External audit
  - Adversarial testing
  - Performance tuning

---

## 🧪 Future Work

- Forward secrecy enhancements (per-frame ratcheting)
- Post-quantum hybrid key exchange
- Frame loss recovery strategies (without weakening guarantees)
- Formal verification of protocol invariants
- Hardware-isolated key handling

---

## 📚 Inspiration & Context

This project explores ideas adjacent to:
- Air-gapped communication systems
- Optical data transfer channels
- Secure protocol design under adversarial conditions

---

## 🙋‍♂️ Author

Paul Clark  
Systems Librarian · AI Builder · Security-Focused Engineer

---

## 📜 License

MIT
