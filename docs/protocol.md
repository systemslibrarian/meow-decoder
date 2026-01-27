# 📜 Meow‑Encode Protocol Specification

**Status:** Source of truth for protocol behavior (January 2026)

This document **defines the protocol exactly as implemented** in the current codebase. It is intended for security review, formal modeling alignment, and reproducible analysis.

## 1) Versioning & Modes

### Manifest versions
- **MEOW2**: Password‑only (legacy compatibility)
- **MEOW3**: Forward secrecy optional (X25519 ephemeral keys). **Default in current code**
- **MEOW4**: Post‑quantum hybrid placeholder (fields defined; not emitted by current encoder)

**Current encoder behavior:** `MAGIC` is `b"MEOW3"` even for password‑only mode. The decoder still accepts legacy `MEOW2` for backward compatibility.

### Modes (encode flags)
- **Password‑only**: no X25519 public key provided
- **Forward secrecy (FS)**: receiver public key provided (X25519)
- **Duress**: optional duress password; only allowed with FS or PQ to avoid manifest size ambiguity

## 2) Cryptographic Parameters (Current Implementation)

### Argon2id (KDF)
From [meow_decoder/crypto.py](../meow_decoder/crypto.py):
- **Memory:** 524,288 KiB (512 MiB)
- **Iterations:** 20
- **Parallelism:** 4
- **Salt:** 16 bytes random (`secrets.token_bytes(16)`)
- **Keyfile (optional):** appended to password bytes before Argon2id (base version)

### AEAD
- **Cipher:** AES‑256‑GCM (via backend)
- **Key:** 32 bytes derived from Argon2id (or X25519+HKDF in FS)
- **Nonce:** 12 bytes random (`secrets.token_bytes(12)`) per encryption

### Length padding
- Compression: `zlib.compress(raw, level=9)`
- **Length padding** applied to compressed data before encryption (see `metadata_obfuscation.add_length_padding()`)

## 3) AAD (Additional Authenticated Data)

**AAD is bound to ciphertext** (GCM):

```
AAD = pack('<QQ', orig_len, comp_len)
    || salt (16 bytes)
    || sha256(plaintext)
    || MAGIC (b"MEOW3")
    || ephemeral_public_key (optional, 32 bytes, FS mode only)
```

- AAD **must match exactly** at decryption or AES‑GCM fails.
- For FS mode, the ephemeral public key is included in AAD to prevent key‑substitution attacks.

## 4) Manifest Format (Frame 0)

Defined in `pack_manifest()` / `unpack_manifest()` in [meow_decoder/crypto.py](../meow_decoder/crypto.py).

### Base fields (115 bytes)
```
MAGIC (5 bytes)
Salt (16 bytes)
Nonce (12 bytes)
orig_len (4 bytes, big‑endian)
comp_len (4 bytes, big‑endian)
cipher_len (4 bytes, big‑endian)
block_size (2 bytes, big‑endian)
k_blocks (4 bytes, big‑endian)
sha256 (32 bytes)
manifest_hmac (32 bytes)
```

### Optional fields
- **Ephemeral X25519 public key:** +32 bytes (FS mode)
- **PQ ciphertext (ML‑KEM‑768):** +1088 bytes (reserved; encoder does not emit currently)
- **Duress hash:** +32 bytes (SHA‑256 of `DURESS_HASH_PREFIX || salt || duress_password`)

### Sizes (current decoder expects)
- **115 bytes**: password‑only (MEOW2 legacy)
- **147 bytes**: forward secrecy (MEOW3)
- **179 bytes**: forward secrecy + duress
- **1235 bytes**: FS + PQ
- **1267 bytes**: FS + PQ + duress

## 5) Manifest Authentication (HMAC)

- **Key derivation:**
  - Password‑only: `Argon2id(password, salt)`
  - FS: X25519 shared secret + password via HKDF (see `x25519_forward_secrecy.py`)
- **HMAC key:** `MANIFEST_HMAC_KEY_PREFIX || encryption_key`
- **HMAC input:** manifest without the `hmac` field, **plus** ephemeral public key when present.

## 6) Frame MACs (DoS‑resistance)

See [meow_decoder/frame_mac.py](../meow_decoder/frame_mac.py).

### Master key
```
frame_master_key = HKDF(encryption_key, salt, info="meow_frame_mac_master_v2")
```

### Per‑frame key
```
frame_key = HKDF(frame_master_key, salt, info="meow_frame_mac_v1" || LE64(frame_index))
```

### MAC
```
mac = HMAC‑SHA256(frame_key, frame_data)[:8]
```

### Packing
```
packed_frame = mac(8 bytes) || frame_data
```

- **Frame 0:** `frame_data = manifest_bytes`
- **Frames 1+:** `frame_data = pack_droplet(droplet)`
- Legacy decode accepts a password‑derived frame master key for backwards compatibility.

## 7) Fountain Encoding (Frames 1+)

- Block size: `EncodingConfig.block_size` (default 512 bytes)
- `k_blocks = ceil(cipher_len / block_size)`
- Droplets: `int(k_blocks * redundancy)`
- Droplet format: `seed(4) || count(2) || indices(2*count) || data(block_size)`

## 8) Session Identity & Replay Rules

- The **session identifier** is implicit in the manifest (salt, nonce, HMAC).
- Frame MACs are bound to `frame_index` and `salt` via the frame master key.
- Decoder rejects frames with invalid MACs and never outputs plaintext without successful authentication.
- Replay across sessions is prevented by MAC binding to per‑session keys.

## 9) Duress/Decoy Semantics (Decode)

- Decoder computes duress hash **before** expensive HMAC verification.
- If duress hash matches:
  - **Decoy mode:** returns deterministic decoy data (no real decryption attempted)
  - **Panic mode (opt‑in):** exits silently
- Real plaintext is **never computed** in the duress path.

## 10) Failure Behavior

- **Invalid manifest length:** hard failure
- **Manifest HMAC failure:** hard failure
- **Frame MAC invalid:** frame rejected (not processed)
- **AEAD auth failure:** decryption fails; no plaintext output
- **QR decode failure:** frame ignored; decoder keeps searching for more droplets

## 11) Implementation References

- Encryption & manifest: [meow_decoder/crypto.py](../meow_decoder/crypto.py)
- Encoding pipeline: [meow_decoder/encode.py](../meow_decoder/encode.py)
- Decoding pipeline: [meow_decoder/decode_gif.py](../meow_decoder/decode_gif.py)
- Frame MACs: [meow_decoder/frame_mac.py](../meow_decoder/frame_mac.py)
- Fountain codes: [meow_decoder/fountain.py](../meow_decoder/fountain.py)

---

## Alignment Notes (Formal Models)

- **ProVerif model** abstracts block/frame contents but preserves key derivation, MAC, AAD binding, and duress behavior.
- **TLA+ model** abstracts cryptography and focuses on state transitions and safety invariants (auth‑then‑output, replay rejection, duress correctness).
- **Verus proofs** cover crypto wrapper invariants (nonce uniqueness, auth‑then‑output, key zeroization) **not the AES‑GCM primitive itself**.
