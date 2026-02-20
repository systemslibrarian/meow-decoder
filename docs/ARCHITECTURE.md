# 🏗️ Meow Decoder - Architecture Documentation

**Version:** 1.1.0 (INTERNAL REVIEW — no external audit)
**Date:** 2026-02-17
**Status:** Production

---

## 📋 **Overview**

Meow Decoder is an optical air-gap file transfer system that combines:
- **Cryptography** (AES-256-GCM, Argon2id, X25519, ML-KEM-768/1024 PQXDH hybrid)
- **Error Correction** (Luby Transform fountain codes — Python + JavaScript)
- **Visual Encoding** (QR codes in GIF animations)
- **Optical Transfer** (screen → camera with 33% frame loss tolerance)

---

## 🎯 **High-Level Architecture**

```
┌──────────────────────────────────────────────────────────────────┐
│                         MEOW DECODER                             │
│                  Air-Gap File Transfer System                    │
└──────────────────────────────────────────────────────────────────┘

┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   SENDER    │    │   OPTICAL    │    │  RECEIVER   │
│   DEVICE    │───▶│   CHANNEL    │───▶│   DEVICE    │
│             │    │  (screen →   │    │             │
│  encode.py  │    │   camera)    │    │ decode.py   │
└─────────────┘    └──────────────┘    └─────────────┘
      │                                       │
      ▼                                       ▼
┌─────────────┐                        ┌─────────────┐
│ secret.pdf  │                        │ secret.pdf  │
│  (plain)    │                        │  (plain)    │
└─────────────┘                        └─────────────┘
```

---

## 🔄 **Data Flow - Encoding Pipeline**

```
INPUT FILE (secret.pdf)
    │
    │  1. READ
    ▼
┌──────────────────────────────────────────┐
│  FILE BYTES (original_data)              │
│  Size: N bytes                           │
└──────────────────────────────────────────┘
    │
    │  2. COMPRESS (zlib level 9)
    ▼
┌──────────────────────────────────────────┐
│  COMPRESSED DATA                         │
│  Size: ~0.7N bytes (typical)             │
└──────────────────────────────────────────┘
    │
    │  3. ENCRYPT (AES-256-GCM + Argon2id)
    ▼
┌──────────────────────────────────────────┐
│  CIPHERTEXT                              │
│  Size: ~0.7N bytes                       │
│  + Nonce (12B)                           │
│  + GCM Tag (16B)                         │
└──────────────────────────────────────────┘
    │
    │  4. FOUNTAIN ENCODE (Luby Transform)
    ▼
┌──────────────────────────────────────────┐
│  FOUNTAIN DROPLETS (kibbles)             │
│  Count: K blocks × 1.5 redundancy        │
│  (33% frame loss tolerance)              │
│  Each: block_size bytes                  │
│  Format: seed + block_indices + XOR_data │
└──────────────────────────────────────────┘
    │
    │  5. QR ENCODE (per droplet)
    ▼
┌──────────────────────────────────────────┐
│  QR CODE FRAMES (paw prints)             │
│  Count: K × 1.5 frames                   │
│  Each: 600×600 pixels                    │
└──────────────────────────────────────────┘
    │
    │  6. GIF CREATION
    ▼
┌──────────────────────────────────────────┐
│  ANIMATED GIF (yarn ball)                │
│  Frames: K × 1.5                         │
│  FPS: 10                                 │
│  Size: ~10 MB (for 1 MB input)          │
└──────────────────────────────────────────┘
    │
    │  7. DISPLAY (optical transfer)
    ▼
OUTPUT GIF (secret.gif)
```

---

## 🔄 **Data Flow - Decoding Pipeline**

```
INPUT GIF (secret.gif)
    │
    │  1. GIF PARSE
    ▼
┌──────────────────────────────────────────┐
│  GIF FRAMES (extracted)                  │
│  Count: K × 1.5 frames                   │
└──────────────────────────────────────────┘
    │
    │  2. QR DECODE (each frame)
    ▼
┌──────────────────────────────────────────┐
│  QR DATA (droplets)                      │
│  Frame 0: Manifest (collar tag)          │
│  Frame 1+: Fountain droplets             │
└──────────────────────────────────────────┘
    │
    │  3. FOUNTAIN DECODE (belief propagation)
    ▼
┌──────────────────────────────────────────┐
│  RECONSTRUCTED CIPHERTEXT                │
│  Size: ~0.7N bytes                       │
└──────────────────────────────────────────┘
    │
    │  4. DECRYPT (AES-256-GCM + verify HMAC)
    ▼
┌──────────────────────────────────────────┐
│  COMPRESSED DATA                         │
│  Size: ~0.7N bytes                       │
└──────────────────────────────────────────┘
    │
    │  5. DECOMPRESS (zlib)
    ▼
┌──────────────────────────────────────────┐
│  ORIGINAL DATA                           │
│  Size: N bytes                           │
└──────────────────────────────────────────┘
    │
    │  6. VERIFY (SHA-256 check)
    ▼
OUTPUT FILE (secret.pdf)
```

---

## 🧩 **Component Architecture**

```
┌───────────────────────────────────────────────────────────────────┐
│                        MEOW DECODER MODULES                       │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   CONFIG    │  │   CRYPTO    │  │  FOUNTAIN   │             │
│  │             │  │             │  │             │             │
│  │ • Settings  │  │ • AES-GCM   │  │ • Encoder   │             │
│  │ • Presets   │  │ • Argon2id  │  │ • Decoder   │             │
│  │ • Validate  │  │ • HMAC      │  │ • Soliton   │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   QR CODE   │  │  GIF HANDLER│  │  CAT UTILS  │             │
│  │             │  │             │  │             │             │
│  │ • Generate  │  │ • Create    │  │ • Sounds    │             │
│  │ • Read      │  │ • Parse     │  │ • Facts     │             │
│  │ • Webcam    │  │ • Optimize  │  │ • Progress  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                   │
│  ┌─────────────────────────────────────────────────┐            │
│  │           SECURITY ENHANCEMENTS                 │            │
│  │                                                 │            │
│  │  • Forward Secrecy (MEOW3)                     │            │
│  │  • Post-Quantum (MEOW4)                        │            │
│  │  • Steganography (Ninja Cat + Phase 1)             │            │
│  │  • Streaming Crypto (Prowling)                 │            │
│  │  • Resume Support                              │            │
│  └─────────────────────────────────────────────────┘            │
│                                                                   │
│  ┌─────────────────────────────────────────────────┐            │
│  │              USER INTERFACES                    │            │
│  │                                                 │            │
│  │  • encode.py (CLI encoder)                     │            │
│  │  • decode_gif.py (CLI decoder + --tamper-report)│            │
│  │  • decode_webcam.py (webcam capture)           │            │
│  │  • meow_dashboard.py (GUI)                     │            │
│  └─────────────────────────────────────────────────┘            │
│                                                                   │
│  ┌─────────────────────────────────────────────────┐            │
│  │              SUPPORT MODULES                    │            │
│  │                                                 │            │
│  │  • canonical_aad.py (deterministic AAD)        │            │
│  │  • tamper_report.py (frame MAC timeline)       │            │
│  │  • mobile/bridge/protocol.py (phone bridge)    │            │
│  └─────────────────────────────────────────────────┘            │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

---

## 🔐 **Security Layers**

```
┌──────────────────────────────────────────────────────────┐
│                   SECURITY ONION                         │
│              (Defense in Depth - 7 Layers)               │
└──────────────────────────────────────────────────────────┘

Layer 7: Air-Gap (optical transfer, no network)
           ↑
Layer 6: Steganography (optional, hides presence — APNG for lossless stego)
           ↑
Layer 5: Per-Frame Ratchet (MSR v1.2: header encryption, key commitment, forward secrecy)
           ↑
Layer 4: Encryption (AES-256-GCM)
           ↑
Layer 3: Authentication (HMAC-SHA256)
           ↑
Layer 2: KDF (Argon2id, memory-hard)
           ↑
Layer 1: Strong Password + Optional Keyfile (2FA)

┌──────────────────────────────────────────────────────────┐
│  Attack Surface: Minimal (endpoint only)                 │
└──────────────────────────────────────────────────────────┘
```

---

## 🦀 **Rust Crypto Backend**

All secret-handling cryptographic operations are implemented in the Rust `crypto_core/` crate and exposed to Python via PyO3 bindings (`meow_crypto_rs` module).

### **Why Rust?**
- **Constant-time operations**: The `subtle` crate provides timing-safe comparisons
- **Secure zeroing**: The `zeroize` crate guarantees secrets are wiped from memory
- **Memory safety**: No buffer overflows or use-after-free vulnerabilities
- **Performance**: Native-speed crypto without Python GIL overhead

### **What the Rust Migration Does — and Does Not — Change**

Moving cryptographic primitives from Python (`cryptography` library) to Rust (`meow_crypto_rs`) does **not** upgrade the underlying algorithms. The math stays exactly the same:

- AES-256-GCM is still 256-bit secure.
- X25519 is still Curve25519 Diffie-Hellman.
- HKDF-SHA256 is still RFC 5869.
- Argon2id is still the same memory-hard KDF with the same parameters.
- ML-KEM-768/1024 is still the same post-quantum KEM.
- The ratchet math, transcript binding, and post-quantum assumptions are unchanged.

**What it improves is the implementation layer** — the code that handles secrets at runtime. In real-world systems, implementation failures (memory leaks, timing side-channels, silent fallbacks) are far more common than broken mathematical primitives. The Rust migration hardens precisely the layer where most real bugs happen.

#### 1. Memory Safety and Secret Hygiene

**Before (Python):** Secrets live in garbage-collected objects. Python's GC makes no guarantee about when — or whether — sensitive bytes are zeroed. Copies may linger in memory across heap allocations, and secrets can be accidentally logged or serialized.

**After (Rust):** The `zeroize` crate provides `Zeroize on Drop` — secrets are deterministically wiped when they leave scope. Rust's ownership model prevents accidental copies, gives the developer controlled secret lifecycles, and eliminates an entire class of memory-inspection risks.

This reduces: secret retention risk, key leakage through memory dumps, accidental logging of sensitive material.

#### 2. Secret Boundary Clarity

**Before:** Cryptographic operations were mixed with protocol orchestration in the same Python modules. Python code touched raw key material directly, making it harder to audit which code paths handle secrets.

**After:** Python handles orchestration only (manifest parsing, fountain coding, QR generation). Rust handles the cryptographic boundary (key derivation, encryption, signing, zeroing). This separation makes the architecture cleaner and makes both halves easier to audit independently.

#### 3. Constant-Time Discipline

**Before (Python):** Python offers limited constant-time guarantees. `hmac.compare_digest()` exists but reasoning about timing behavior across the interpreter, bytecode, and GC is difficult. Custom comparisons are nearly impossible to make genuinely constant-time in CPython.

**After (Rust):** The `subtle` crate provides explicit constant-time types (`Choice`, `CtEq`) with well-understood timing properties. Constant-time comparisons are enforced at the type level, not by convention. This narrows the timing-leak attack surface considerably.

#### 4. Auditability

The Rust crypto core (`crypto_core/src/`) is a deliberately small, tightly-scoped surface. It contains only primitive operations — no protocol logic, no I/O, no user-facing code. This makes it:

- Easier for external reviewers to read in a single sitting
- Easier to verify ownership and data-flow properties
- Compatible with Rust-native formal verification tools (Verus, Kani)
- Backed by a well-audited crate ecosystem (`aes-gcm`, `argon2`, `x25519-dalek`, `hkdf`)

#### 5. Elimination of Silent Fallbacks

**Before:** A misconfigured environment could silently fall back to a Python crypto path that lacked constant-time guarantees and memory zeroing — with no indication to the user.

**After:** The Rust backend is **required**. If `meow_crypto_rs` is not available, the system fails closed with a clear error. CI enforces `RUST_BACKEND_REQUIRED=1`, and an AST-based import scanner blocks `from cryptography` in all production modules. There are no shadow crypto paths, no partial migrations, no "works locally but insecure in production" surprises.

#### Honest Summary

| | Before Rust Migration | After Rust Migration |
|---|---|---|
| **Protocol strength** | Strong (AES-256-GCM, Argon2id, X25519, ML-KEM) | Identical — no algorithm changes |
| **Implementation risk** | Moderate (Python secret handling, GC, timing) | Lower (Rust ownership, zeroize, subtle) |
| **Crypto boundary** | Blurred (Python touches secrets) | Clean (Rust = secrets, Python = orchestration) |
| **Fallback behavior** | Silent Python fallback possible | Fail-closed, CI-enforced |
| **Auditability** | Harder (crypto spread across Python modules) | Easier (compact Rust core) |

This is not increasing cryptographic strength. It is increasing **implementation security**, **operational robustness**, **secret hygiene**, **side-channel discipline**, and **architectural integrity**. That is a meaningful upgrade.

### **Backend Functions (52 PyO3 bindings)**

```
┌───────────────────────────────────────────────────────────────────┐
│                    meow_crypto_rs Module                          │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Key Derivation:          Symmetric Crypto:      Hashing:         │
│  ├─ derive_key_argon2id   ├─ aes_gcm_encrypt     ├─ sha256        │
│  ├─ derive_key_hkdf       ├─ aes_gcm_decrypt     ├─ hmac_sha256   │
│  ├─ hkdf_extract          └─ aes_ctr_crypt       └─ hmac_verify   │
│  └─ hkdf_expand                                                   │
│                                                                   │
│  Key Exchange:            Utilities:             Post-Quantum:    │
│  ├─ x25519_generate       ├─ constant_time_cmp   ├─ mlkem768_*    │
│  ├─ x25519_exchange       ├─ secure_zero         └─ mlkem1024_*   │
│  └─ x25519_pub_from_priv  └─ secure_random                        │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### **CI Enforcement**
- `RUST_BACKEND_REQUIRED=1` environment gate — CI fails if Rust backend unavailable
- AST-based import scanner blocks `from cryptography` in production modules
- Golden vector regression tests verify Python/Rust output parity

### **Production vs Non-Production Code**

All production `meow_decoder/*.py` modules route crypto through `crypto_backend.CryptoBackend()` (Rust).
No production module imports `cryptography` at module level or runtime.

**Non-production / legacy modules (exempt from enforcement):**

| Module | Status | Reason |
|--------|--------|--------|
| `crypto_DEBUG.py` | Debug-only | Verbose logging variant, not imported by production |
| `pq_crypto_real.py` | Dead code | `raise RuntimeError` before imports; kept for audit trail |
| `pq_signatures.py` | Experimental | Ed25519 not yet in Rust backend; `_PQ_EXPERIMENTAL = True` |
| `x25519_forward_secrecy.py` | Legacy PEM fallback | New keys use `MEOW_X25519` format via Rust; legacy PEM path imports `cryptography` only when loading old-format keys |
| `spec_v12/` | Reference spec | Not imported by production entrypoints |

---

## 🏛️ **Architectural Layer Boundaries**

Meow Decoder's codebase is organized into five strict layers. These boundaries exist to prevent refactors, AI-assisted edits, or well-meaning contributions from flattening the project's personality, renaming cryptographic primitives, altering protocol invariants, or reintroducing Python `cryptography` imports into production code.

Every module in the project belongs to exactly one layer. Code in a given layer may call downward (Layer 4 → Layer 3 → Layer 2 → Layer 1) but never upward.

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 5 — Demos / Documentation / Branding                 │
│  examples/, docs/, README.md, assets/, Jupyter notebooks    │
├─────────────────────────────────────────────────────────────┤
│  Layer 4 — Themed Façade API (Cat Personality)               │
│  meow_encode.py, cat_utils.py, cat_errors.py,               │
│  meow_gui_enhanced.py, gui_logo_example.py, logo_eyes.py    │
├─────────────────────────────────────────────────────────────┤
│  Layer 3 — Protocol Orchestration                            │
│  crypto.py, encode.py, decode_gif.py, ratchet.py,            │
│  forward_secrecy.py, fountain.py, pq_hybrid.py,              │
│  schrodinger_encode.py, quantum_mixer.py, frame_mac.py       │
├─────────────────────────────────────────────────────────────┤
│  Layer 2 — crypto_backend (Python ↔ Rust Bridge)             │
│  crypto_backend.py → CryptoBackend()                         │
├─────────────────────────────────────────────────────────────┤
│  Layer 1 — crypto_core (Rust)                                │
│  crypto_core/src/ → meow_crypto_rs (PyO3)                    │
│  pure_crypto.rs, aead_wrapper.rs, nonce.rs, lib.rs           │
└─────────────────────────────────────────────────────────────┘
```

### **Layer 1 — `crypto_core` (Rust)**

**Location:** `crypto_core/src/`

Pure cryptographic primitives only: AES-256-GCM, Argon2id, HKDF-SHA256, X25519, SHA-256, HMAC-SHA256, ML-KEM-768/1024. Built with the `subtle` crate (constant-time) and `zeroize` crate (memory zeroing).

**Rules:**
1. No humor in function names. Identifiers are cryptographic domain terms (`aes_gcm_encrypt`, `hkdf_expand`, `x25519_exchange`).
2. No renaming of domain separation labels. Strings like `"meow_pqxdh_v1"`, `"meow-fs-block"`, `"meow-ratchet-chain"` are protocol constants bound in formal proofs and test vectors.
3. No playful identifiers inside primitive logic.
4. Zero jokes below this layer. External auditors read this code.

### **Layer 2 — `crypto_backend` (Python ↔ Rust Bridge)**

**Location:** `meow_decoder/crypto_backend.py`

A thin wrapper that exposes Rust primitives to Python via the `CryptoBackend` class and `get_default_backend()` factory.

**Rules:**
1. Thin wrapper only — each method delegates directly to `meow_crypto_rs`. No multi-step crypto logic.
2. No business logic. Protocol decisions belong in Layer 3.
3. No `cryptography` library imports. The Python `cryptography` package is permanently banned from this module and all production modules.
4. Stable primitive names. Method names (`derive_key_argon2id`, `aes_gcm_encrypt`, `x25519_generate_keypair`, etc.) are the API contract.

### **Layer 3 — Protocol Orchestration**

**Location:** `meow_decoder/crypto.py`, `encode.py`, `decode_gif.py`, `ratchet.py`, `forward_secrecy.py`, `fountain.py`, `pq_hybrid.py`, `schrodinger_encode.py`, `quantum_mixer.py`, `frame_mac.py`, `double_ratchet.py`, and related modules.

Protocol logic that composes Layer 2 primitives into the MEOW protocol: manifest packing (MEOW2–MEOW5), AAD construction, fountain coding, symmetric ratchet (MSR v1.2), PQXDH key exchange, Schrödinger mode, QR/GIF encoding.

**Rules:**
1. All crypto calls go through `CryptoBackend()`. Never import raw primitives.
2. No renaming of protocol invariants — manifest magic bytes, mode bytes, domain separation strings, struct layouts, and AAD field ordering are frozen.
3. Light comments are fine, but do not rename variables that track protocol state (`chain_key`, `message_key`, `ephemeral_public_key`, `pq_ciphertext`).
4. Fail-closed on all MAC verification (`ValueError` on failure, never silently disable).
5. Constant-time comparisons for all authentication checks.

### **Layer 4 — Themed Façade API (Cat Personality)**

**Location:** `meow_decoder/meow_encode.py`, `cat_utils.py`, `cat_errors.py`, `meow_gui_enhanced.py`, `gui_logo_example.py`, `logo_eyes.py`, `ascii_qr.py`, and similar user-facing wrappers.

Playful, cat-themed wrappers around Layer 3 operations. `CollarTag` for manifests, `CatError` for exceptions, themed progress messages, GUI skins with cat imagery, CLI names like `meow-encode`.

**Rules:**
1. Safe to introduce playful wrapper names (`whisker_check()`, `purr_progress()`, etc.).
2. Must call Layer 2/3 functions internally. Personality is a naming layer, not a reimplementation.
3. Must not alter semantics — no changing encryption parameters, skipping verification, or adding new cryptographic behavior.
4. No "fun encryption" or "cat cipher" — only delegate to established primitives.

### **Layer 5 — Demos / Documentation / Branding**

**Location:** `examples/`, `docs/`, `README.md`, `QUICKSTART.md`, `assets/`, Jupyter notebooks, HTML demos.

Everything that helps humans understand and enjoy the project: example scripts, browser demos, JavaScript fountain codes, cat imagery, markdown documentation.

**Rules:**
1. Fully allowed to be playful — cat puns, emoji, personality, creative writing all welcome.
2. Must not contradict the protocol spec. Playful framing is fine; incorrect security claims are not.
3. Demo code may use simplified patterns but must not demonstrate insecure usage without explicit warnings.

---

## 🔐 **Crypto Core Is Sacred**

The following invariants are load-bearing. Violating any one of them constitutes a security regression, not a style preference.

| Invariant | Why It Exists | How It Is Enforced |
|-----------|---------------|-------------------|
| **No `from cryptography` in production modules** | Rust backend provides constant-time operations and memory zeroing that Python `cryptography` cannot guarantee | AST-based import scanner (`tests/test_crypto_enforcement.py`); CI gate `RUST_BACKEND_REQUIRED=1` |
| **Manifest magic bytes and mode bytes are frozen** | `MEOW2`=`0x02`, `MEOW3`=`0x03`, `MEOW4`=`0x04`, `MEOW5`=`0x05`, duress=`\|0x80` — changing them breaks all existing encoded files | Golden vector tests (`tests/test_golden_vectors.py`) |
| **Domain separation strings are immutable** | `"meow_pqxdh_v1"`, `"meow-fs-block"`, `"meow-ratchet-chain"`, etc. are bound in formal proofs and interop test vectors | `verify_domain_separation.sh`; formal model checks |
| **AAD field ordering is fixed** | `orig_len ‖ comp_len ‖ salt ‖ sha256 ‖ magic ‖ ephemeral_pub ‖ pq_ciphertext` — reordering silently breaks authentication | Tamper detection tests (`tests/test_security.py`) |
| **HMAC-then-use for manifests** | Manifest HMAC must be verified before any field is trusted; skipping this enables oracle attacks | Adversarial tests (`tests/test_adversarial.py`) |
| **Fail-closed MAC verification** | `ValueError` on invalid MAC; silent MAC bypass is a critical vulnerability | Unit tests assert `ValueError` is raised, never caught |
| **Argon2id production parameters** | 512 MiB memory, 20 iterations, 4 threads — lowering them weakens brute-force resistance | Config tests; `MEOW_TEST_MODE` flag for CI only |
| **Nonce uniqueness** | LRU cache (10K cap) + HKDF-derived synthetic IV prevents catastrophic nonce reuse | Nonce reuse guard tests |
| **Fountain code frame format** | `FOUNTAIN:<k>:<block_size>:<length>:<droplet_b64>` — changing this breaks Python ↔ JavaScript interop | Interop tests across both implementations |
| **Rust primitive function names** | `aes_gcm_encrypt`, `derive_key_hkdf`, `x25519_exchange`, etc. — renaming them breaks every Layer 3 module | Layer 2 API contract; compilation and import tests |

### What "Sacred" Means in Practice

- **Do not rename** Layer 1 or Layer 2 function signatures without updating every call site, every test, and every formal proof.
- **Do not add** new cryptographic algorithms to Layer 4 or Layer 5. All crypto lives in Layer 1; orchestration lives in Layer 3.
- **Do not weaken** Argon2id parameters, MAC verification, or AAD bindings for convenience, performance, or "simplicity."
- **Do not bypass** the `CryptoBackend()` abstraction. If a module needs a cryptographic operation, it calls Layer 2.

---

## 🎨 **Where Personality Is Allowed**

Meow Decoder's cat-themed identity is part of the project, but it must not leak into security-critical code. The table below defines where personality is safe and where it is forbidden.

| Layer | Personality Level | What Is OK | What Is Not OK |
|-------|:-----------------:|------------|----------------|
| Layer 1 (Rust primitives) | **None** | `aes_gcm_encrypt`, `hkdf_expand` | `paws_encrypt`, `meow_hkdf` |
| Layer 2 (crypto_backend) | **None** | `CryptoBackend.derive_key_argon2id` | `CatCryptoBackend.scratch_key` |
| Layer 3 (protocol orchestration) | **Minimal** | Conversational code comments; technical names (`pack_manifest`, `ratchet_step`) | Replacing `HMAC-SHA256` with `whisker-hash` in protocol code |
| Layer 4 (themed façade) | **Full** | `CollarTag`, `CatError`, `purr_progress()` — but must delegate to Layers 2/3 | Implementing a custom cipher, skipping MAC checks |
| Layer 5 (demos/docs) | **Full** | Cat art, emoji, playful tutorials, `meow-encode` CLI name | Documenting incorrect security properties |

### Encouraged Patterns

- **Layer 4 wrapper:** `class CollarTag` that internally calls `pack_manifest()` / `unpack_manifest()`
- **Layer 4 error:** `class CatError(Exception)` with a friendly message wrapping a raw `ValueError`
- **Layer 5 docs:** *"Your secret file is now wearing its invisible collar!"*
- **Layer 5 CLI:** `meow-encode` as the user-facing command (delegates to `encode.py`)

### Anti-Patterns (Do Not Do)

- Renaming `aes_gcm_encrypt` → `cat_encrypt` in Layer 1 or 2
- Adding `meow_` prefix to Rust function names in `pure_crypto.rs`
- Using cat puns in domain separation strings (`"meow-purr-chain"` instead of `"meow-ratchet-chain"`)
- Creating a `FunCipher` class that implements novel crypto in Layer 4
- Replacing protocol variable names (`chain_key` → `yarn_key`) in Layer 3

---

## 🔒 **Cryptographic Architecture**

### **MEOW2: Base Encryption**

```
PASSWORD + SALT
    │
    │  Argon2id (512 MiB, 20 iter)
    ▼
256-bit MASTER KEY
    │
    ├─────────────────┬─────────────────┐
    │                 │                 │
    ▼                 ▼                 ▼
AES-256-GCM      HMAC Key         (unused)
Encryption       (manifest
                 auth)
```

### **MEOW3: Forward Secrecy**

```
PASSWORD + SALT
    │
    │  Argon2id
    ▼
MASTER KEY
    │
    │  HKDF
    ▼
INITIAL CHAIN KEY
    │
    ├──▶ Block 0 Key ──▶ Encrypt Block 0
    │         │
    │         │  HKDF (ratchet)
    │         ▼
    ├──▶ Block 1 Key ──▶ Encrypt Block 1
    │         │
    │         │  HKDF (ratchet)
    │         ▼
    └──▶ Block 2 Key ──▶ Encrypt Block 2
          ...

(Each block key is independent!)
```

### **MEOW5 (default) / MEOW4 (paranoid): PQXDH Post-Quantum Hybrid**

```
PASSWORD + SALT
    │
    │  Argon2id
    ▼
MASTER KEY
    │
    ├───────────────┬────────────────────┐
    │               │                    │
    ▼               ▼                    ▼
Generate        Generate             Generate
X25519          ML-KEM-768 (MEOW5)   HKDF Keys
Keypair         ML-KEM-1024 (MEOW4)
    │               │
    │  ECDH         │  KEM Encap
    ▼               ▼
Classical     Quantum
Shared (32B)  Shared (32B)
    │               │
    └───────┬───────┘
            │  PQXDH Two-Step HKDF
            │
            │  1. PRK = HMAC-SHA256(0x00*32, classical_ss || pq_ss)
            │  2. transcript = SHA256(domain || eph_pub || recv_cls_pub || recv_pq_pub || pq_ct)
            │  3. key = HKDF-Expand(PRK, "meow_pqxdh_v1" || transcript, 32)
            ▼
    HYBRID SHARED SECRET
            │
            ▼
    AES-256-GCM Key
```

---

## 🌊 **Fountain Code Architecture**

```
┌────────────────────────────────────────────────────┐
│            LUBY TRANSFORM FOUNTAIN                 │
└────────────────────────────────────────────────────┘

ENCODING:

Input Data (N bytes)
    │
    │  Split into K blocks
    ▼
┌────┬────┬────┬────┬────┬────┐
│ B0 │ B1 │ B2 │ B3 │ B4 │ B5 │  K blocks
└────┴────┴────┴────┴────┴────┘
  │    │    │    │    │    │
  └──┬─┴──┬─┴──┬─┴──┬─┴──┬─┘
     │    │    │    │    │
     │  Robust Soliton Distribution
     │  (determines degree d)
     ▼
┌──────────────────────────────┐
│   SELECT d random blocks      │
│   XOR them together           │
└──────────────────────────────┘
     │
     ▼
  DROPLET (can reconstruct infinite!)

DECODING (Belief Propagation):

Collect droplets until K blocks solved
    │
    ▼
┌────────────────────────────────────┐
│  DEGREE 1 DROPLETS                │
│  (single block)                   │
│  → Immediately solved!            │
└────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────┐
│  DEGREE 2+ DROPLETS               │
│  (multiple blocks)                │
│  → XOR out solved blocks          │
│  → May become degree 1            │
│  → Cascade solving!               │
└────────────────────────────────────┘
    │
    ▼
ALL K BLOCKS SOLVED → SUCCESS!
```

### 🌐 **JavaScript Implementation (Web Demo)**

The fountain code implementation is available in both **Python** (CLI) and **JavaScript** (web demo):

**File:** `examples/fountain-codes.js` (414 lines)

**Classes:**
- `FountainEncoder`: Generate droplets from source data
- `FountainDecoder`: Reconstruct via belief propagation
- `Droplet`: Serialization (pack/unpack for QR transmission)
- `RobustSolitonDistribution`: Optimal degree sampling
- `SeededRandom`: Deterministic PRNG (reproducible block selection)

**Integration Points:**

```
[ENCODING - wasm_browser_example.html]
User encrypts large file (>2500 bytes)
    ↓
FountainEncoder(payloadBytes, kBlocks, blockSize)
    ↓
Generate k×1.5 droplets (50% redundancy)
    ↓
Each droplet → Pack to bytes → Base64 → QR frame
    Frame format: FOUNTAIN:<k>:<block_size>:<length>:<droplet_b64>
    ↓
Animated QR cycling through droplet frames

[DECODING - webcam scanner]
Point camera at animated QR
    ↓
jsQR detects frame: "FOUNTAIN:5:600:2847:AAB..."
    ↓
Parse metadata, initialize FountainDecoder(5, 600, 2847)
    ↓
Droplet.unpack(base64ToBytes(droplet_b64), 600)
    ↓
decoder.addDroplet(droplet)  → belief propagation
    ↓
Progress: "Collecting: 8 scanned, 80% decoded (4/5 blocks)"
    ↓
decoder.isComplete() → true
    ↓
recovered = decoder.getData(originalLength)
    ↓
Decrypt with password → Original file!
```

**Frame Loss Tolerance:**
- **33% loss**: With 1.5× redundancy (k → 1.5k droplets), can lose 33% of frames
- **Automatic retry**: Keep scanning until enough droplets collected
- **Visual progress**: Real-time feedback shows decode percentage

**Performance:**
- Encoding: ~10ms for typical payloads (1000 blocks)
- Decoding: O(n × k) belief propagation, runs in real-time
- Memory: O(k × block_size) - stores only decoded blocks

See [docs/FOUNTAIN_CODES_INTEGRATION.md](FOUNTAIN_CODES_INTEGRATION.md) for full technical details.

---

## 📊 **Module Dependencies**

```
┌──────────────┐
│  encode.py   │
└──────┬───────┘
       │
       ├──▶ config.py (load settings)
       ├──▶ crypto.py (encrypt)
       ├──▶ fountain.py (encode)
       ├──▶ qr_code.py (generate QR)
       ├──▶ gif_handler.py (create GIF)
       └──▶ cat_utils.py (fun features)

┌──────────────┐
│ decode_gif.py│
└──────┬───────┘
       │
       ├──▶ config.py (load settings)
       ├──▶ crypto.py (decrypt)
       ├──▶ fountain.py (decode)
       ├──▶ qr_code.py (read QR)
       ├──▶ gif_handler.py (parse GIF)
       └──▶ cat_utils.py (fun features)

┌───────────────────┐
│ meow_dashboard.py │ (GUI)
└────────┬──────────┘
         │
         ├──▶ dearpygui (UI framework)
         ├──▶ encode.py (background threads)
         ├──▶ decode_gif.py (background threads)
         └──▶ cat_utils.py (progress, sounds)

SECURITY MODULES (optional):
├──▶ forward_secrecy.py (MEOW3)
├──▶ pq_hybrid.py (MEOW5/MEOW4, primary PQ module — PQXDH transcript binding)
├──▶ pq_crypto_real.py (DEPRECATED — use pq_hybrid.py)
├──▶ ninja_cat_ultra.py (steganography)
├──▶ prowling_mode.py (low-memory)
└──▶ resume_secured.py (resume support)
```

---

## 🔄 **State Machine - Encoding**

```
[IDLE]
  │
  │  encode.py --input file.pdf
  ▼
[READING FILE]
  │
  │  Success
  ▼
[COMPRESSING]
  │
  │  zlib compress
  ▼
[ENCRYPTING]
  │
  │  AES-GCM encrypt
  ▼
[FOUNTAIN ENCODING]
  │
  │  Generate K×1.5 droplets
  ▼
[QR GENERATION]
  │
  │  Create QR for each droplet
  ▼
[GIF CREATION]
  │
  │  Combine frames into GIF
  ▼
[WRITING OUTPUT]
  │
  │  Save secret.gif
  ▼
[COMPLETE] ✅
  │
  │  (Optional: wipe source)
  ▼
[DONE]
```

---

## 🔄 **State Machine - Decoding**

```
[IDLE]
  │
  │  decode_gif.py --input secret.gif
  ▼
[READING GIF]
  │
  │  Parse frames
  ▼
[QR DECODING]
  │
  │  Frame 0 → Manifest
  │  Frame 1+ → Droplets
  ▼
[MANIFEST VALIDATION]
  │
  │  Verify HMAC
  ▼
[FOUNTAIN DECODING]
  │
  │  Collect droplets
  │  Belief propagation
  ▼
[CHECKING COMPLETION]
  │
  ├─ All blocks solved? ─▶ [DECRYPTING]
  │                           │
  └─ Need more? ─▶ [QR DECODING]
                    (retry/continue)

[DECRYPTING]
  │
  │  AES-GCM decrypt
  ▼
[DECOMPRESSING]
  │
  │  zlib decompress
  ▼
[VERIFYING]
  │
  │  Check SHA-256
  ▼
[WRITING OUTPUT]
  │
  │  Save secret.pdf
  ▼
[COMPLETE] ✅
```

---

## 🎯 **Trust Boundaries**

```
┌─────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                         │
│                                                         │
│  • User's computer (sender/receiver)                   │
│  • Python interpreter                                  │
│  • Meow Decoder code                                   │
│  • Cryptography libraries                              │
│  • User's memory/disk                                  │
│                                                         │
└─────────────────────────────────────────────────────────┘
                         │
                         │  TRUST BOUNDARY
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   UNTRUSTED ZONE                        │
│                                                         │
│  • Optical channel (screen → camera)                   │
│  • Anyone who can see the screen                       │
│  • Recorded video/photos                               │
│  • GIF file in transit                                 │
│                                                         │
└─────────────────────────────────────────────────────────┘

KEY INSIGHT:
Even if attacker controls UNTRUSTED zone, they
cannot decrypt without password (cryptography).
```

---

## 📈 **Performance Characteristics**

```
┌──────────────────────────────────────────────────────┐
│              PERFORMANCE PROFILE                     │
│          (1 MB input file, typical setup)            │
└──────────────────────────────────────────────────────┘

ENCODING BREAKDOWN:
┌────────────────┬──────────┬──────────┐
│ Phase          │ Time     │ % Total  │
├────────────────┼──────────┼──────────┤
│ Read file      │  0.1s    │   1%     │
│ Compress       │  1.2s    │  14%     │
│ Encrypt        │  0.3s    │   4%     │
│ Fountain       │  2.1s    │  25%     │
│ QR generation  │  4.2s    │  49%     │ ← Bottleneck!
│ GIF creation   │  0.7s    │   8%     │
├────────────────┼──────────┼──────────┤
│ TOTAL          │  8.6s    │ 100%     │
└────────────────┴──────────┴──────────┘

DECODING BREAKDOWN:
┌────────────────┬──────────┬──────────┐
│ Phase          │ Time     │ % Total  │
├────────────────┼──────────┼──────────┤
│ Read GIF       │  0.5s    │  12%     │
│ QR decode      │  2.1s    │  50%     │ ← Bottleneck!
│ Fountain       │  0.8s    │  19%     │
│ Decrypt        │  0.3s    │   7%     │
│ Decompress     │  0.3s    │   7%     │
│ Verify SHA     │  0.2s    │   5%     │
├────────────────┼──────────┼──────────┤
│ TOTAL          │  4.2s    │ 100%     │
└────────────────┴──────────┴──────────┘

MEMORY USAGE:
┌────────────────┬────────────┐
│ Mode           │ Peak RAM   │
├────────────────┼────────────┤
│ Normal encode  │  ~200 MB   │
│ Normal decode  │  ~150 MB   │
│ Prowling mode  │   ~50 MB   │ ← Low-memory!
└────────────────┴────────────┘
```

---

## 🔍 **Attack Surface Analysis**

```
┌──────────────────────────────────────────────────────┐
│                ATTACK SURFACES                       │
└──────────────────────────────────────────────────────┘

1. INPUT VALIDATION
   ├─ File paths        [LOW RISK]
   ├─ Password input    [MEDIUM RISK - weak passwords]
   ├─ Keyfile format    [LOW RISK - validation in place]
   └─ Config files      [LOW RISK - JSON parsing]

2. CRYPTOGRAPHIC
   ├─ Key derivation    [LOW RISK - uses Argon2id]
   ├─ Encryption        [LOW RISK - uses cryptography lib]
   ├─ HMAC              [LOW RISK - constant-time compare]
   └─ Random generation [LOW RISK - uses secrets module]

3. DATA PROCESSING
   ├─ Compression       [LOW RISK - zlib is mature]
   ├─ QR encoding       [LOW RISK - qrcode lib]
   ├─ QR decoding       [MEDIUM RISK - pyzbar can crash on bad data]
   └─ GIF handling      [MEDIUM RISK - Pillow has had vulns]

4. DEPENDENCIES
   ├─ Python stdlib     [LOW RISK]
   ├─ meow_crypto_rs    [LOW RISK - Rust crypto backend, constant-time]
   ├─ Pillow            [MEDIUM RISK - monitor CVEs]
   ├─ opencv-python     [MEDIUM RISK - C++ code]
   └─ Third-party libs  [MEDIUM RISK - supply chain]

5. SIDE CHANNELS
   ├─ Timing            [LOW RISK - Rust `subtle` crate, constant-time]
   ├─ Power analysis    [HIGH RISK - no mitigation]
   ├─ EM emissions      [HIGH RISK - no mitigation]
   └─ Cache timing      [LOW RISK - Rust bitsliced AES]

6. OPERATIONAL
   ├─ Password entry    [HIGH RISK - keyloggers]
   ├─ Screen recording  [HIGH RISK - endpoint compromise]
   ├─ Memory forensics  [MEDIUM RISK - key zeroing helps]
   └─ Physical access   [HIGH RISK - rubber-hose]

OVERALL RISK: MEDIUM
(Depends heavily on endpoint security and password strength)
```

---

## 🎨 **Extension Points**

Want to add new features? Here are the extension points:

### **1. New Manifest Version**
```python
# In crypto.py — new manifest versions follow this pattern
# MEOW2 through MEOW5 are already implemented:
#   MODE_MEOW2 = 0x02 (password-only)
#   MODE_MEOW3 = 0x03 (X25519 forward secrecy)
#   MODE_MEOW4 = 0x04 (ML-KEM-1024 + X25519, paranoid)
#   MODE_MEOW5 = 0x05 (ML-KEM-768 + X25519, default PQ hybrid)
# Adding a new version requires updating pack_manifest/unpack_manifest
```

### **2. New Steganography Algorithm**
```python
# In ninja_cat_ultra.py
class SuperNinjaCat(NinjaCatUltra):
    """Even stealthier than ULTRA!"""

    def apply_quantum_stego(self, frame):
        # Your quantum stego code
```

### **3. New Cat Breed Preset**
```python
# In cat_utils.py
CAT_BREED_PRESETS[CatBreed.RAGDOLL] = {
    "stego_palette": "fluffy-cream",
    "success_message": "😻 Ragdoll says: So soft, so secure!",
    # Your preset
}
```

### **4. New GUI Tab**
```python
# In meow_dashboard.py
def _create_statistics_tab(self):
    """Add a statistics/analytics tab."""
    with dpg.tab(label="📊 Statistics"):
        # Your tab UI
```

---

## 🌐 **WASM Browser Architecture**

The crypto core is also available as a WebAssembly module for browser-based encryption:

```
┌─────────────────────────────────────────────────────────────────┐
│                    BROWSER ENVIRONMENT                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────────┐    ┌──────────────────┐    ┌─────────────┐ │
│  │   Main Thread │    │   Web Worker     │    │  Service    │ │
│  │  (UI)         │<──>│  (crypto-worker) │    │  Worker     │ │
│  │               │    │                  │    │  (caching)  │ │
│  │ wasm_browser_ │    │ crypto_core.wasm │    │  sw.js      │ │
│  │ example.html  │    │ + JS bindings    │    │             │ │
│  └───────────────┘    └──────────────────┘    └─────────────┘ │
│         │                      │                               │
│         ▼                      ▼                               │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │                    WASM CRYPTO CORE                       │ │
│  │  ┌─────────────┐ ┌──────────────┐ ┌───────────────────┐  │ │
│  │  │ AES-256-GCM │ │ Argon2id KDF │ │ X25519 / ML-KEM   │  │ │
│  │  │  (AEAD)     │ │ (64-512 MiB) │ │ (hybrid PQ)       │  │ │
│  │  └─────────────┘ └──────────────┘ └───────────────────┘  │ │
│  │  Rust → wasm-pack → crypto_core.wasm                      │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### **WASM Feature Parity**

| Feature | CLI (Python) | WASM Browser | Notes |
|---------|:------------:|:------------:|-------|
| AES-256-GCM | ✅ | ✅ | Identical AEAD |
| Argon2id | ✅ 512/20 | ✅ Configurable | Web: 4 security levels |
| X25519 | ✅ | ✅ | Forward secrecy |
| ML-KEM-1024 | ✅ | ✅ | Requires `wasm-pq` feature |
| Schrödinger Mode | ✅ | ✅ | Dual-secret deniability |
| Fountain Codes | ✅ | ✅ | Full support (Python CLI + JavaScript web demo) |
| Steganography | ✅ Level 1-5 | ⚠️ Level 1-2 | Canvas limitations |
| Hardware Keys | ✅ | ❌ | WebAuthn planned |

### **Building WASM**

```bash
# Standard build
make build-wasm

# With Post-Quantum ML-KEM-1024
wasm-pack build crypto_core --target web --release --features wasm-pq
```

---

## 🐾 **Cat-Themed Architecture Fun Facts**

1. **Hissing** (encryption) happens in `crypto.py` 🔐
2. **Purring** (decryption) also in `crypto.py` 😻
3. **Kibbles** (droplets) are dispensed by `fountain.py` 🍖
4. **Paw Prints** (QR codes) made by `qr_code.py` 🐾
5. **Yarn Balls** (GIFs) created by `gif_handler.py` 🧶
6. **Nine Lives** (forward secrecy) in `forward_secrecy.py` 🐱
7. **Quantum Nine Lives** (post-quantum) in `pq_hybrid.py` 🔮 *(pq_crypto_real.py is deprecated)*
8. **Ninja Cat** (steganography) in `ninja_cat_ultra.py` 🥷
9. **Prowling** (low-memory) in `prowling_mode.py` 🐾
10. **Collar Tags** (manifests) in all the above! 🏷️

---

**🐾 "The architecture is like a cat: elegant, mysterious, and always lands on its feet!" 😺**

---

**Last Updated:** 2026-02-17
**Version:** 1.1.0 (INTERNAL REVIEW — no external audit)
**Status:** Production
