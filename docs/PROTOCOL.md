# Meow Decoder Protocol Specification (v1.0)

**Status:** Normative protocol definition for the v1.0 security‑reviewed release.

This document defines the **byte‑level formats**, state transitions, and **failure rules** for Meow‑Decoder’s air‑gapped QR/GIF transfer. Any deviation is a protocol error and must be handled as specified.

---

## 1. Versioning & Modes

### Manifest versions (MAGIC)
- **MEOW2**: Legacy password‑only (backward compatibility decode only).
- **MEOW3**: Default for password‑only and X25519 forward secrecy.
- **MEOW4**: Reserved for post‑quantum hybrid (PQ ciphertext present).

### Modes
- **Password‑only:** no receiver public key.
- **Forward secrecy (FS):** receiver X25519 public key present.
- **PQ hybrid:** PQ ciphertext present (requires FS fields).
- **Duress:** duress tag present (requires FS or PQ to avoid size collision).

---

## 2. Cryptographic Parameters

### KDF (Argon2id)
- Salt: 16 bytes random.
- Memory: 524,288 KiB.
- Iterations: 20.
- Parallelism: 4.

### AEAD
- Cipher: AES‑256‑GCM.
- Key: 32 bytes derived (Argon2id or X25519+HKDF).
- Nonce: 12 bytes random per encryption.

### Frame MAC
- HMAC‑SHA256 truncated to 8 bytes.
- Per‑frame key derived via HKDF from a per‑session master key.

---

## 3. AAD (Additional Authenticated Data)

AAD is bound to ciphertext and **must match exactly** at decryption:

```
AAD = LE64(orig_len) || LE64(comp_len) || salt || sha256 || MAGIC
AAD += ephemeral_public_key (32 bytes, if present)
```

- If AAD verification fails, decryption MUST fail and emit no plaintext.

---

## 4. Manifest Format (Frame 0, bytes)

**Base format (115 bytes):**
```
MAGIC (5)
SALT (16)
NONCE (12)
ORIG_LEN (4, BE)
COMP_LEN (4, BE)
CIPHER_LEN (4, BE)
BLOCK_SIZE (2, BE)
K_BLOCKS (4, BE)
SHA256 (32)
HMAC (32)
```

**Optional fields in order:**
- EPHEMERAL_PUBLIC_KEY (32, FS)
- PQ_CIPHERTEXT (1088, PQ hybrid)
- DURESS_TAG (32, duress)

**Valid lengths:**
- 115  (base)
- 147  (base + FS)
- 179  (base + FS + duress)
- 1235 (base + FS + PQ)
- 1267 (base + FS + PQ + duress)

### Duress tag
```
DURESS_KEY = SHA256(DURESS_HASH_PREFIX || SALT || DURESS_PASSWORD)
DURESS_TAG = HMAC‑SHA256(DURESS_KEY, MANIFEST_CORE)
```
`MANIFEST_CORE` excludes HMAC and DURESS_TAG.

---

## 5. Manifest Authentication (HMAC)

```
HMAC_KEY = MANIFEST_HMAC_KEY_PREFIX || ENCRYPTION_KEY
HMAC = HMAC‑SHA256(HMAC_KEY, MANIFEST_CORE_WITH_OPTIONALS)
```

`MANIFEST_CORE_WITH_OPTIONALS` includes EPHEMERAL_PUBLIC_KEY, PQ_CIPHERTEXT, and DURESS_TAG when present.

---

## 6. Frame Format (QR payload)

### Frame MAC (optional)
```
FRAME = MAC(8) || FRAME_DATA
```

### Frame data
- **Frame 0:** Manifest bytes.
- **Frame 1+:** Droplet bytes: `seed(4) || count(2) || indices(2*count) || data(block_size)`.

---

## 7. Encoder State Machine

1. Read file
2. Compress (zlib)
3. Optional length padding
4. Encrypt (AES‑GCM with AAD)
5. Build manifest + HMAC (+ duress tag if enabled)
6. Fountain encode ciphertext into droplets
7. Wrap frames with MAC (if enabled)
8. Encode to QR frames → GIF

---

## 8. Decoder State Machine

1. Extract frames
2. Decode QR payloads
3. Parse manifest (length and MAGIC validation)
4. If duress tag present: verify duress tag with entered password
5. Verify manifest HMAC
6. If frame MACs present: verify each frame before use
7. Decode fountain droplets until complete
8. Decrypt with AES‑GCM (AAD required)
9. Verify SHA‑256
10. Output plaintext

---

## 9. Failure Rules (MUST)

- **Invalid manifest length:** hard fail.
- **Invalid MAGIC:** hard fail.
- **Duress tag mismatch:** do **not** enter duress path.
- **Manifest HMAC failure:** hard fail.
- **Frame MAC failure:** reject frame and continue.
- **AEAD failure:** hard fail, no plaintext output.
- **SHA‑256 mismatch:** hard fail.
- **Truncated droplet:** reject droplet.

All failures must be **safe and boring**: no partial plaintext and no detailed oracle messages.

---

## 10. Version Compatibility

- Decoders MUST accept MEOW2 for legacy password‑only files.
- Encoders MUST emit MEOW3+ for new files.
- PQ hybrid uses PQ ciphertext field; if absent, decoder MUST treat as non‑PQ.

---

## 11. References

- Manifest/crypto: meow_decoder/crypto.py
- Frame MAC: meow_decoder/frame_mac.py
- Encode pipeline: meow_decoder/encode.py
- Decode pipeline: meow_decoder/decode_gif.py
