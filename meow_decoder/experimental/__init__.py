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

Primary crypto path:
  - crypto.py           — AES-256-GCM + Argon2id, pluggable backend (PRIMARY)
  - crypto_backend.py   — Unified crypto interface, requires Rust backend
  - x25519_forward_secrecy.py — X25519 ephemeral key agreement (PRIMARY)

Quarantined modules (deprecation warnings emitted on import):
  - crypto_enhanced.py         — Legacy AES-256-GCM with Python-native crypto
  - crypto_DEBUG.py            — Verbose debug variant (weaker Argon2 params)
  - encode_DEBUG.py            — Verbose debug variant of encode.py
  - forward_secrecy_x25519.py  — Native-lib X25519 (use x25519_forward_secrecy.py)
  - hardware_keys.py           — Legacy standalone hardware key manager

Note: The quarantined .py files currently still reside in meow_decoder/ with
deprecation warnings. They will be physically moved here once the file move
can be executed (pending terminal access). See experimental/README.md.
"""
