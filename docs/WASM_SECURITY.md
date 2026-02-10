# 🌐 WASM Browser Demo - Security Analysis

**Version:** 1.0.0  
**Date:** 2026-02-10  
**Status:** Production

> *"The cat prowls the web — but always with nine lives of security."*

---

## 📋 Overview

This document provides a comprehensive security analysis of the Meow Decoder WASM browser demo. The web demo provides **cryptographic parity** with the CLI when properly configured.

---

## 🔐 Cryptographic Implementation

### Algorithm Comparison

| Component | Python CLI | Rust WASM | Library | Parity |
|-----------|------------|-----------|---------|--------|
| AEAD | AES-256-GCM | AES-256-GCM | `aes-gcm` | ✅ Identical |
| KDF | Argon2id | Argon2id | `argon2` | ✅ Configurable |
| Key Exchange | X25519 | X25519 | `x25519-dalek` | ✅ Identical |
| Post-Quantum | ML-KEM-1024 | ML-KEM-1024 | `ml-kem` | ✅ Identical |
| Hash | SHA-256 | SHA-256 | `sha2` | ✅ Identical |
| MAC | HMAC-SHA256 | HMAC-SHA256 | `hmac` | ✅ Identical |
| KDF2 | HKDF-SHA256 | HKDF-SHA256 | `hkdf` | ✅ Identical |
| RNG | `os.urandom` | Web Crypto API | `getrandom` (wasm_js) | ✅ Secure |

### Key Derivation Parameters

The Python CLI uses fixed production parameters:

```
Memory:     512 MiB (524288 KiB)
Iterations: 20
Parallelism: 4
```

The WASM demo provides **4 security levels** to balance browser performance:

| Level | Memory | Iterations | Parallelism | CLI Parity | Recommendation |
|-------|--------|------------|-------------|:----------:|----------------|
| ⚡ Fast | 64 MiB | 3 | 1 | ❌ | Demo/testing only |
| 🔒 Standard | 128 MiB | 8 | 1 | ❌ | Low-value data |
| 🛡️ High | 256 MiB | 15 | 1 | ⚠️ | Sensitive data |
| 🔐 Paranoid | 512 MiB | 20 | 1 | ✅ | **Life-critical** |

⚠️ **CRITICAL:** For data where lives depend on security, **always select "Paranoid" level**.

### Why WASM Uses Parallelism=1

WASM runs single-threaded by default. While SharedArrayBuffer enables multi-threading, most browsers require specific COOP/COEP headers. We use `parallelism=1` with increased memory/iterations to compensate.

---

## 🛡️ Security Properties

### What the WASM Demo Guarantees

| Property | Guarantee | Implementation |
|----------|-----------|----------------|
| **Confidentiality** | AES-256-GCM AEAD encryption | Same as CLI |
| **Integrity** | GCM authentication tag | Same as CLI |
| **Key Derivation** | Argon2id memory-hard | Configurable levels |
| **Forward Secrecy** | X25519 ephemeral keys | Full parity |
| **Quantum Resistance** | ML-KEM-1024 hybrid | Requires `wasm-pq` build |
| **Plausible Deniability** | Schrödinger dual-secret | Full parity |
| **RNG Security** | Web Crypto API | Standards-based |

### What the WASM Demo Does NOT Guarantee

| Limitation | Reason | Mitigation |
|------------|--------|------------|
| **Memory Zeroing** | WASM memory not guaranteed zeroed | `zeroize` crate best-effort; close tab after use |
| **Side Channels** | No constant-time guarantees in WASM | Use for air-gap scenarios only |
| **Extension Attacks** | Browser extensions can read DOM | Use private/incognito mode |
| **Clipboard Security** | OS clipboard accessible | Clear after copying keys |
| **Screen Capture** | OS can screenshot | Physical security |
| **Hardware Keys** | No HSM/TPM access | WebAuthn planned |

---

## 🔑 Key Management

### LocalStorage Keys

The web demo stores key pairs in browser localStorage:

| Key | Content | Format |
|-----|---------|--------|
| `meow_fs_keypair` | X25519 Forward Secrecy key pair | JSON (base64) |
| `meow_pq_keypair` | ML-KEM + X25519 Post-Quantum keys | JSON (base64) |
| `meow_duress_hash` | Hashed panic password | Argon2id hash |

⚠️ **WARNING:** LocalStorage is **not encrypted**. Anyone with filesystem access can read these keys.

### Key Lifecycle

```
Generate          →  Store          →  Use           →  Destroy
(button click)       (localStorage)    (decrypt ops)    (Duress mode)
```

### Duress Mode (Panic Password)

If coerced, entering the **panic password** will:
1. Immediately wipe all localStorage keys
2. Display fake decoy content
3. Log destruction to console (for forensic verification)

---

## 🌐 Browser Security Requirements

### Recommended Configuration

For maximum security when using the web demo:

| Setting | Recommendation | Reason |
|---------|----------------|--------|
| **Mode** | Private/Incognito | Prevents key persistence |
| **Extensions** | Disabled | Extensions can access page |
| **Other Tabs** | None | JavaScript isolation |
| **Console** | Closed | Prevents key logging |
| **Screenshot** | Disabled | Prevents image capture |

### Recommended Browsers (Ranked)

1. **Tor Browser** (hardened Firefox, no extensions)
2. **Firefox** (strict privacy settings, no extensions)
3. **Chrome/Edge** (private mode, no extensions)
4. **Safari** (private mode)

### Network Security

- The demo works **fully offline** after initial load
- Service worker caches all assets
- No data is sent to any server
- All crypto happens client-side in the WASM module

---

## 📊 Threat Model Comparison

### CLI vs WASM Threat Model

| Threat | CLI (Python) | WASM (Browser) | Difference |
|--------|:------------:|:--------------:|------------|
| Brute-force (online) | Argon2id 512/20 | Argon2id configurable | ⚠️ User must select Paranoid |
| Brute-force (offline) | Argon2id 512/20 | Argon2id configurable | ⚠️ User must select Paranoid |
| Memory forensics | Best-effort zeroing | Best-effort zeroing | ≈ Similar |
| Side-channel (local) | Rust constant-time | WASM best-effort | ⚠️ WASM weaker |
| Malicious app | OS protection | ⚠️ Extension risk | ⚠️ Browser weaker |
| Key storage | Process memory | LocalStorage | ⚠️ Browser persistent |
| Quantum computers | ML-KEM-1024 | ML-KEM-1024 | ✅ Same |

### Attacker Capabilities (Assumed)

| Attacker | CLI Protection | WASM Protection |
|----------|:--------------:|:---------------:|
| Network eavesdropper | ✅ Full | ✅ Full |
| Has encrypted QR/GIF | ✅ Full | ✅ Full (Paranoid) |
| Controls JS environment | N/A | ❌ None |
| Physical access (running) | ⚠️ Partial | ⚠️ Partial |
| Physical access (powered off) | ✅ Full | ✅ Full |
| Quantum computer (future) | ✅ PQ mode | ✅ PQ mode |

---

## 🔧 Build Security

### Standard Build

```bash
make build-wasm
# or
wasm-pack build crypto_core --target web --release
```

Creates WASM with:
- AES-256-GCM
- Argon2id
- X25519 forward secrecy

### Post-Quantum Build (Recommended)

```bash
wasm-pack build crypto_core --target web --release --features wasm-pq
```

Creates WASM with above PLUS:
- ML-KEM-1024 (Kyber) for quantum-resistant key exchange
- Hybrid X25519 + ML-KEM mode

### Verifying the Build

After building, verify the exported functions:

```bash
grep -E 'export function' crypto_core/pkg/crypto_core.js | head -20
```

Expected functions include:
- `derive_key` (Argon2id)
- `encrypt` / `decrypt` (AES-256-GCM)
- `x25519_generate_keypair` / `x25519_diffie_hellman`
- `mlkem_generate_keypair` / `mlkem_encapsulate` / `mlkem_decapsulate` (PQ build only)
- `encrypt_hybrid_pq` / `decrypt_hybrid_pq` (PQ build only)

---

## ✅ Security Checklist

Before using the web demo for sensitive data:

- [ ] Built with `--features wasm-pq` for post-quantum protection
- [ ] Using private/incognito browser mode
- [ ] Disabled all browser extensions
- [ ] Closed all other browser tabs
- [ ] Selected **"Paranoid" security level** (512 MiB, 20 iter)
- [ ] Physical security (no screen capture, no shoulder surfing)
- [ ] Plan to clear localStorage or use Duress mode after use
- [ ] Working offline (network disconnected) for maximum air-gap

---

## 📚 References

- [OWASP Argon2id Recommendations](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [WebCrypto API Specification](https://www.w3.org/TR/WebCryptoAPI/)
- [ML-KEM FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [wasm-pack Documentation](https://rustwasm.github.io/docs/wasm-pack/)

---

**🐾 "Security in the browser — as strong as the weakest link. Choose Paranoid mode for life-critical data."**

---

**Last Updated:** 2026-02-10  
**Version:** 1.0.0  
**Status:** Production
