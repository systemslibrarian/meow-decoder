# 🐾 Cat Style Guide — Personality Rules for Meow Decoder

> **Purpose:** Prevent future refactors — human or AI — from stripping the project's personality OR accidentally renaming cryptographic invariants. Both failures are real risks, and this guide draws the line between them.

---

## Why This Guide Exists

Meow Decoder has two properties that must coexist:

1. **Serious cryptography.** AES-256-GCM, Argon2id, X25519, ML-KEM, HKDF, HMAC — implemented in Rust, formally verified where possible, and tested with 1000+ assertions.
2. **Cat-themed personality.** Collar tags, kibbles, purring progress bars, whisker checks — a deliberate design choice that makes the project approachable without weakening security.

Past refactors have accidentally flattened one or the other. This guide prevents both.

---

## ✅ Allowed — Where the Cat Lives

### Playful Wrapper Names (Layer 4 Façade)

Cat-themed function names are encouraged in `meow_decoder/cat_api.py` and similar façade modules, as long as they delegate to real primitives without adding logic.

```python
# ✅ Good — personality wrapper, delegates directly
def purr_encrypt(key, nonce, plaintext, aad=None):
    """Encrypt with a contented purr. (AES-256-GCM)"""
    return _get_backend().aes_gcm_encrypt(key, nonce, plaintext, aad)

# ✅ Good — themed name, identical semantics
def scratch_mac(key, message):
    """Leave a scratch mark — compute a MAC. (HMAC-SHA256)"""
    return _get_backend().hmac_sha256(key, message)

# ✅ Good — playful class wrapping a protocol object
class CollarTag:
    """A cat's collar tag — wraps a MEOW manifest."""
    def __init__(self, manifest_bytes):
        self._manifest = unpack_manifest(manifest_bytes)
```

### Cat-Themed Comments Above Crypto Boundaries

Brief personality in comments is fine at module and section level in Layer 3+.

```python
# ✅ Good — playful section divider in encode.py
# --- 🐾 Attach the collar tag (manifest) to frame 0 ---
manifest_frame = pack_manifest(...)

# ✅ Good — lighthearted docstring in a Layer 4 module
"""
🐱 Meow Encoder — Turn secrets into yarn balls (animated QR GIFs).
All the real hissing happens in crypto_backend.
"""
```

### Cat Tone in Demos and Documentation

Layers 4–5 (demos, docs, README, QUICKSTART, examples) are fully open to personality.

```markdown
<!-- ✅ Good — README blurb -->
🔒 Under the Fur: All secret-handling cryptography now lives in the Rust
core. The cat may look playful — but the claws are constant-time.

<!-- ✅ Good — QUICKSTART encouragement -->
🐱 Your secret file is now wearing its invisible collar!
```

### Themed CLI Messages

User-facing CLI output can (and should) be fun.

```
🐱 Encoding secret.txt...
✅ Encrypted (AES-256-GCM)
✅ Generated 18 QR frames (1.5x redundancy)
✅ Saved to secret.gif — the cat is packed!
```

### Cat-Themed Error Classes

```python
# ✅ Good — wraps ValueError with a friendly message
class CatError(Exception):
    """Something scared the cat."""
    pass

class WhiskerCheckFailed(CatError):
    """HMAC verification failed — someone touched the whiskers."""
    pass
```

---

## 🚫 Forbidden — What Must Never Change

### Renaming Domain Separation Labels

Domain separation strings are protocol constants. They appear in formal proofs, test vectors, and interop specs. Changing them silently breaks every existing encoded file.

```python
# ❌ FORBIDDEN — renaming a domain separation label
info = b"kitty_kdf_magic"        # NO
info = b"purr_pqxdh_v1"          # NO
info = b"meow-purr-chain"        # NO

# ✅ CORRECT — these are frozen protocol constants
info = b"meow_pqxdh_v1"          # YES — do not touch
info = b"meow-fs-block"          # YES — do not touch
info = b"meow-ratchet-chain"     # YES — do not touch
```

### Renaming HKDF Info Strings

HKDF `info` parameters are domain separators. They are not branding.

```python
# ❌ FORBIDDEN
derived = backend.hkdf_expand(prk, b"cat_treats_key", 32)

# ✅ CORRECT
derived = backend.hkdf_expand(prk, b"meow-ratchet-chain", 32)
```

### Renaming Nonce Derivation Logic

Nonce construction is security-critical. Changing variable names, field order, or derivation steps risks catastrophic nonce reuse.

```python
# ❌ FORBIDDEN — renaming nonce variables for fun
catnip_nonce = os.urandom(12)          # NO
yarn_iv = hkdf_expand(prk, info, 12)   # NO

# ✅ CORRECT — standard cryptographic names
nonce = os.urandom(12)
synthetic_iv = hkdf_expand(prk, info, 12)
```

### Altering Ratchet Invariants

The symmetric ratchet (MSR v1.2) has 10 HKDF domain separation constants, header encryption masks, and key commitment tags. These are protocol-level invariants.

```python
# ❌ FORBIDDEN — renaming ratchet state variables
yarn_key = hkdf(...)         # NO — this is chain_key
paw_key = hkdf(...)          # NO — this is message_key

# ✅ CORRECT
chain_key = hkdf(...)
message_key = hkdf(...)
```

### Adding Jokes Inside Primitive Logic

Layers 1–2 (Rust crypto core, crypto_backend.py) must contain zero humor. Auditors read this code.

```rust
// ❌ FORBIDDEN — joke in Rust primitive
fn paws_gcm_encrypt(key: &[u8], nonce: &[u8], pt: &[u8]) -> Vec<u8> { ... }

// ✅ CORRECT
fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], pt: &[u8]) -> Vec<u8> { ... }
```

```python
# ❌ FORBIDDEN — joke in crypto_backend.py
class CatCryptoBackend:
    def scratch_key(self, password, salt): ...

# ✅ CORRECT
class CryptoBackend:
    def derive_key_argon2id(self, password, salt, ...): ...
```

### Modifying Rust Primitive Function Names

The 16 PyO3 bindings in `meow_crypto_rs` are the API contract. Every Layer 3 module depends on these exact names.

```
❌ FORBIDDEN renames:
  aes_gcm_encrypt    → cat_encrypt
  derive_key_hkdf    → knead_key
  x25519_exchange    → hiss_exchange
  hmac_sha256        → scratch_hash
  secure_zero        → shred_yarn

✅ These names are permanent:
  aes_gcm_encrypt, aes_gcm_decrypt, aes_ctr_crypt
  derive_key_argon2id, derive_key_hkdf
  hkdf_extract, hkdf_expand
  hmac_sha256, hmac_sha256_verify
  sha256
  x25519_generate_keypair, x25519_exchange, x25519_public_from_private
  constant_time_compare, secure_zero, secure_random
```

### Renaming Manifest Constants

```python
# ❌ FORBIDDEN
MANIFEST_MAGIC = b"KITTY"
MODE_BYTE_PURR = 0x02

# ✅ CORRECT — these are frozen
MANIFEST_MAGIC = b"MEOW"
MODE_BYTE_MEOW2 = 0x02
MODE_BYTE_MEOW3 = 0x03
MODE_BYTE_MEOW4 = 0x04
MODE_BYTE_MEOW5 = 0x05
```

---

## Quick Reference Table

| Area | Personality? | Example |
|------|:---:|---------|
| Rust function names (`crypto_core/src/`) | **No** | `aes_gcm_encrypt` stays `aes_gcm_encrypt` |
| `crypto_backend.py` method names | **No** | `CryptoBackend.derive_key_argon2id` stays as-is |
| Domain separation labels | **No** | `"meow_pqxdh_v1"` is frozen |
| HKDF info strings | **No** | `"meow-ratchet-chain"` is frozen |
| Protocol variable names | **No** | `chain_key`, `message_key`, `ephemeral_public_key` |
| Manifest magic/mode bytes | **No** | `MEOW2`=`0x02` through `MEOW5`=`0x05` |
| AAD field ordering | **No** | Fixed struct layout, never reorder |
| `cat_api.py` wrapper names | **Yes** | `purr_encrypt()`, `scratch_mac()` |
| CLI output messages | **Yes** | `"🐱 Encoding secret.txt..."` |
| Docstrings in Layer 4+ | **Yes** | `"""Encrypt with a contented purr."""` |
| Section comments in Layer 3 | **Light** | `# --- 🐾 Attach the collar tag ---` |
| README / QUICKSTART / demos | **Yes** | Cat puns, emoji, playful framing |
| THREAT_MODEL / SECURITY_INVARIANTS | **No** | Formal, precise, no jokes |

---

## 🔐 Crypto Core Is Sacred

The cryptographic core is the trust anchor of this project. It is not a branding surface.

**What "sacred" means:**

- **Do not rename** any function in `crypto_core/src/` or `crypto_backend.py` for aesthetic reasons.
- **Do not alter** domain separation strings, HKDF info labels, nonce derivation, AAD field order, or manifest byte layouts.
- **Do not weaken** Argon2id parameters, MAC verification, or AAD bindings for convenience.
- **Do not add** new cryptographic algorithms in Layer 4 or Layer 5. All crypto lives in Layer 1; orchestration lives in Layer 3.
- **Do not bypass** the `CryptoBackend()` abstraction. If a module needs crypto, it calls Layer 2.

**The personality exists _because_ the core is sacred.** Cat wrappers like `purr_encrypt()` are safe precisely because they add zero logic — they forward arguments unchanged to `aes_gcm_encrypt()` and return the result untouched. The moment a wrapper modifies a parameter, skips a check, or introduces a new algorithm, it stops being personality and becomes a security defect.

The cat is playful. The claws are constant-time. Both must remain true.

---

*See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#-architectural-layer-boundaries) for the full 5-layer boundary model.*
