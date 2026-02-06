"""
Meow Decoder — Experimental / Quarantined Modules

These modules are NOT part of the primary crypto pipeline and should NOT be
imported by production code (encode.py, decode_gif.py).

They are preserved here for:
  - Reference implementations
  - Debug/development variants
  - Legacy compatibility testing
  - Potential future consolidation

WARNING: Modules in this directory may use weaker Argon2id parameters,
         bypass the Rust backend, or lack side-channel hardening.
         DO NOT use for production encryption.

Quarantined modules:
  - crypto_enhanced.py   — Legacy AES-256-GCM with Python-native crypto (256 MiB/10 iter)
  - crypto_DEBUG.py      — Verbose debug variant of crypto.py (256 MiB/10 iter)
  - encode_DEBUG.py      — Verbose debug variant of encode.py
  - forward_secrecy_x25519.py — Native-lib X25519 (use x25519_forward_secrecy.py instead)
  - hardware_keys.py     — Legacy standalone hardware key manager
"""
