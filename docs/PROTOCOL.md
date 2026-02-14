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

AAD is bound to ciphertext and **must match exactly** at decryption.

**Canonical construction** (see `meow_decoder/canonical_aad.py`):

```
AAD = LE64(orig_len) || LE64(comp_len) || salt || sha256 || MAGIC
AAD += ephemeral_public_key (32 bytes, if present)
```

- Field order is deterministic (version-aware).
- If AAD verification fails, decryption MUST fail and emit no plaintext.
- Backward compatible with MEOW2/MEOW3/MEOW4 manifests.

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

## 11. MEOW4 Post‑Quantum Hybrid Mode

### 11.1 KEM Algorithm
- **Algorithm:** ML‑KEM‑1024 (FIPS 203 / Kyber1024).
- **Ciphertext size:** 1568 bytes (ML‑KEM‑1024).
- **Shared secret:** 32 bytes.

> **Implementation note (2026‑02‑14):** The manifest serialisation in
> `crypto.py` currently reserves 1088 bytes for PQ ciphertext—the size of
> ML‑KEM‑**768**, not ML‑KEM‑1024.  Until this is corrected, the
> full MEOW4 encode pipeline is **not wired up**.  The Tamarin and
> ProVerif models verify the target design; the implementation gap is
> tracked in `todo-formal.md`.

### 11.2 Hybrid Key Derivation

```
classical_ss = X25519(ephemeral_sk, receiver_pk)        // 32 bytes
pq_ss        = ML-KEM-1024.Decaps(receiver_sk, kem_ct)  // 32 bytes
combined_ikm = classical_ss || pq_ss                     // 64 bytes

shared_secret = HKDF-SHA256(
    salt  = "",
    ikm   = combined_ikm,
    info  = "meow_hybrid_pq_v1",
    len   = 32
)
```

- Classical‑only fallback uses `info = "meow_classical_only_v1"`.
- The combined secret provides IND‑CCA2 security if **either**
  X25519 or ML‑KEM‑1024 is unbroken (dual‑PRF combiner via HKDF).

### 11.3 KEM Ciphertext Binding

The KEM ciphertext and ephemeral public key are bound to the manifest
via HMAC‑SHA256 over `MANIFEST_CORE_WITH_OPTIONALS` (§5), which includes
the PQ ciphertext bytes.

```
HMAC_INPUT includes: ... || EPHEMERAL_PK (32) || PQ_CIPHERTEXT (1568)
```

> **Note:** The KEM ciphertext is **not** independently bound in the
> AES‑GCM AAD (`build_canonical_aad` does not accept a `pq_ciphertext`
> parameter).  This is acceptable because the manifest HMAC—verified
> before any decryption—covers the ciphertext.  An attacker who
> substitutes or truncates the KEM ciphertext will fail HMAC
> verification and hit the uniform `error_auth_failed` path.

### 11.4 Downgrade Prevention

A MEOW4 session **MUST NOT** silently fall back to MEOW3.

- The encoder selects the manifest version before encryption; a MEOW4
  manifest includes the 1568‑byte PQ ciphertext field, making its wire
  length (≥1267 bytes) unambiguously distinguishable from MEOW3 (147 or
  179 bytes).
- If the decoder receives a manifest whose length does not include the PQ
  field, it MUST parse it as MEOW3 (not MEOW4).  The expected combined
  key will not match the AEAD tag, causing hard fail.

> **Implementation gap (2026‑02‑14):** The decoder has no "expected
> version" configuration—it accepts whatever manifest version it
> receives.  A MitM who replaces a MEOW4 GIF with a MEOW3 GIF forged
> under a different key would succeed if and only if they know the
> password.  Since the password is the root trust anchor in the
> password‑only threat model, this is not a practical downgrade;
> however, a future version SHOULD allow the receiver to pin to MEOW4.

### 11.5 Formal Verification Coverage

| Property | Tool | Model | Status |
|---|---|---|---|
| PQ OE (real ≈ duress) | Tamarin `--diff` | `MeowDuressEquivPQ.spthy` | CI‑gated |
| Hybrid KEM binding | ProVerif | `meow_encode.pv` (EncoderPQ) | Verified |
| KEM ct in AAD | ProVerif | `meow_encode.pv` L828 | Verified |
| Downgrade blocked | Tamarin | `MeowDuressEquivPQ.spthy` (Decode_PQ_Downgrade) | CI‑gated |
| Downgrade fail‑closed | TLA+ | `MeowEncode.tla` (`MEOW4NeverFallsBackToClassical`) | Verified |
| KEM ct integrity | Tamarin | `MeowDuressEquivPQ.spthy` (`PQ_KEM_Ct_Integrity`) | CI‑gated |
| Failure uniformity | Tamarin | `MeowDuressEquivPQ.spthy` (`PQ_Failure_Uniform_Observable`) | CI‑gated |
| No KEM binding → OE fails | Tamarin negative | `NEGATIVE_NoKEMBinding.spthy` | CI‑gated |
| Leaked failure reason → uniformity fails | Tamarin negative | `NEGATIVE_LeaksFailureReason.spthy` | CI‑gated |

---

## 12. References

- Manifest/crypto: meow_decoder/crypto.py
- Frame MAC: meow_decoder/frame_mac.py
- Encode pipeline: meow_decoder/encode.py
- Decode pipeline: meow_decoder/decode_gif.py
