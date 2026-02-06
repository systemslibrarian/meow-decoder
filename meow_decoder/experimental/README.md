# ⚠️ Experimental / Quarantined Modules

> **WARNING:** Modules in this directory are NOT part of the primary crypto pipeline
> and MUST NOT be imported by production code (`encode.py`, `decode_gif.py`).

## Why are these here?

These modules were moved out of the main `meow_decoder/` package because they are:
- Legacy duplicates superseded by the primary crypto path
- Debug variants with weaker parameters or verbose logging
- Standalone implementations that have been consolidated

## Quarantined Modules

| Module | Reason | Replacement |
|--------|--------|-------------|
| `crypto_enhanced.py` | Legacy AES-256-GCM with Python-native crypto | `crypto.py` + `crypto_backend.py` (Rust) |
| `crypto_DEBUG.py` | Verbose debug variant, weaker Argon2 params (256 MiB/10 iter) | `crypto.py` |
| `encode_DEBUG.py` | Verbose debug variant of encode.py | `encode.py` |
| `forward_secrecy_x25519.py` | Native-lib X25519 duplicate | `x25519_forward_secrecy.py` |

## Primary Crypto Path

The production pipeline uses:
- **`meow_decoder/crypto.py`** — AES-256-GCM + Argon2id, pluggable backend
- **`meow_decoder/crypto_backend.py`** — Unified interface, requires Rust `meow_crypto_rs`
- **`meow_decoder/x25519_forward_secrecy.py`** — X25519 ephemeral key agreement
- **`crypto_core/`** (Rust) — Formally verified primitives with `zeroize` guarantees

## Can I use these for testing?

Yes — tests may import from these modules for coverage and regression testing.
Always use `try/except ImportError` or `pytest.importorskip()` when importing.

---

*🐾 "Not every yarn ball belongs in the litter box." — The Cat*
