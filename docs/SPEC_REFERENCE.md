# 📜 Spec v1.2/v1.3.1 Reference Implementation

The spec-aligned implementation lives under `meow_decoder/spec_v12` and provides a complete reference for the protocol specification.

---

## Features

- **Unified Ed25519 identity keys** (RFC 8410 conversion to X25519 for ECDH)
- **Sign‑header‑then‑encrypt‑payload** with AAD binding
- **Dynamic GIF insertion/extraction** (MEOW‑PAYLOAD)
- **Constant‑order multi‑tier processing**

---

## v1.2 Improvements Summary

| Improvement | Description |
|-------------|-------------|
| Stateless design | Removed `file_id` |
| Enhanced AAD | Includes signature field (prevents stripping) |
| Early detection | Recipient public key in header |
| Flexible embedding | Dynamic GIF insertion (no fixed offset) |
| Side-channel resistant | Constant‑time multi‑tier handling |

---

## Usage Example

### Single-Tier Encode/Decode

```python
from meow_decoder.spec_v12 import SoftwareBackend, encode_file, decode_file

# Generate keys
sender = SoftwareBackend()
recipient = SoftwareBackend()
sender_sk, sender_pk = sender.generate_ed25519_keypair()
recipient_sk, recipient_pk = recipient.generate_ed25519_keypair()

# Encode
gif_carrier = open("carrier.gif", "rb").read()
encrypted_gif = encode_file(b"secret", recipient_pk, sender_sk, gif_carrier)

# Decode
plaintext = decode_file(encrypted_gif, sender_pk, recipient_sk)
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `PyNaCl` | Required for Ed25519↔X25519 conversion |
| `cryptography` | Core crypto primitives |

---

## Security Notes

| Requirement | Rationale |
|-------------|-----------|
| Uniform error messages | All decryption failures must return "Decryption failed" |
| Constant-order processing | Multi‑tier decode must process all tiers in constant order |

---

## Related Documentation

- [Protocol Spec](PROTOCOL.md) — Byte-level protocol specification
- [Architecture](ARCHITECTURE.md) — Technical deep-dive
- [Security Invariants](SECURITY_INVARIANTS.md) — Formal invariant specification

---

*See the main [README.md](../README.md) for quick start and installation.*
