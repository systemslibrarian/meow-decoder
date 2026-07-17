# Meow Decoder Protocol Specification (v1.0)

**Status:** Normative protocol definition for the v1.0 internally-reviewed release.

This document defines the **byte‑level formats**, state transitions, and **failure rules** for Meow‑Decoder’s air‑gapped QR/GIF transfer. Any deviation is a protocol error and must be handled as specified.

---

## 1. Versioning & Modes

### Manifest versions (MAGIC)
- **MEOW2**: Legacy password‑only (backward compatibility decode only).
- **MEOW3**: Default for password‑only and X25519 forward secrecy.
- **MEOW4**: Post‑quantum hybrid paranoid (ML-KEM-1024 + X25519).
- **MEOW5**: Post‑quantum hybrid default (ML-KEM-768 + X25519).

### Modes
- **Password‑only:** no receiver public key.
- **Forward secrecy (FS):** receiver X25519 public key present.
- **PQ hybrid:** PQ ciphertext present (requires FS fields).
- **Duress:** duress tag present (requires FS or PQ to avoid size collision).

---

## 2. Cryptographic Parameters

### KDF (Argon2id)
- Salt: 16 bytes random.
- Default preset: **paranoid** (512 MiB / 20 iterations / 4 threads).
- Available presets (selectable via `MEOW_KDF_PRESET` env or `--preset` CLI):

| Preset | Memory | Iterations | Parallelism | Approx. Time |
|--------|--------|------------|-------------|---------------|
| `paranoid` (default) | 512 MiB | 20 | 4 | ~10-40s |
| `balanced` | 256 MiB | 8 | 4 | ~4-15s |
| `activist-fast` | 194 MiB | 4 | 4 | ~2-8s |
| `test` | 32 MiB | 1 | 1 | ~0.1s |

> ⚠️ Even strong Argon2id parameters do not protect against a state actor
> who obtains the real password via coercion.

See `meow_decoder/argon2_presets.py` for implementation.

### AEAD
- Cipher: AES‑256‑GCM.
- Key: 32 bytes derived (Argon2id or X25519+HKDF).
- Nonce: 12 bytes deterministic via HKDF (see §2.1).

### §2.1 Nonce Generation (Synthetic IV)

Nonces are derived deterministically to prevent catastrophic reuse:

```
nonce = HKDF-SHA-256(
    IKM  = transfer_root_key,
    salt = frame_counter (u64 BE) || SHA-256(transfer_manifest),
    info = b"aes-gcm-nonce-v1",
    len  = 12
)
```

**Properties:**
- Deterministic: same inputs → same nonce (SIV property).
- Collision-resistant: requires HKDF-SHA-256 collision.
- Crash-safe: no persistent state; frame_counter from transfer context.
- Multi-process safe: manifest hash is unique per transfer session.
- Schrödinger isolation: `additional_context` byte distinguishes sub-streams.

**Reuse guard:** `NonceGenerator` tracks used counters per session.
Duplicate `frame_counter` raises `RuntimeError` (fail-closed).

See `meow_decoder/nonce.py` and `tests/security/test_nonce_uniqueness.py`.

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
AAD += pq_ciphertext (1088 bytes for MEOW5 / 1568 bytes for MEOW4, if present)
```

- Field order is deterministic (version-aware).
- If AAD verification fails, decryption MUST fail and emit no plaintext.
- Backward compatible with MEOW2/MEOW3/MEOW4/MEOW5 manifests.

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
- PQ_CIPHERTEXT (1088, PQ hybrid ML-KEM-768 / 1568, PQ hybrid ML-KEM-1024)
- DURESS_TAG (32, duress)

**Valid lengths:**
- 115  (base)
- 147  (base + FS)
- 179  (base + FS + duress)
- 1235 (base + FS + PQ ML-KEM-768 / MEOW5)
- 1267 (base + FS + PQ ML-KEM-768 + duress)
- 1715 (base + FS + PQ ML-KEM-1024 / MEOW4)
- 1747 (base + FS + PQ ML-KEM-1024 + duress)

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

### 5.1 Manifest Signature Status

- Hybrid manifest-signing is **mandatory by default** (`SIGNING_MANDATORY = True` in `manifest_signing.py`).
- Both Ed25519 (classical) and ML-DSA-65 (FIPS 204 post-quantum) signatures are required; failure of either raises `ValueError`.
- Decoder rejects unsigned manifests with a fail-closed `ValueError` unless `MEOW_MANIFEST_SIGNING=off` is explicitly set (legacy compatibility only).
- Signature bytes are carried out-of-band relative to the encrypted payload and verified before any manifest field is trusted (verification-before-trust).
- Downgrade to unsigned is **not** permitted in high-security mode; `MEOW_MANIFEST_SIGNING=off` disables this protection and must only be used for reading legacy pre-signing transfers.

---

## 6. Frame Format (QR payload)

### Frame MAC (optional)
```
FRAME = MAC(8) || FRAME_DATA
```

### Frame data
- **Frame 0:** Manifest bytes.
- **Optional signature metadata frames:** MAC'd `MSGC` chunks immediately after frame 0.
- **Remaining frames:** Droplet bytes: `seed(4) || count(2) || indices(2*count) || data(block_size)`.

The Python QR renderer encodes each binary frame as Base85 ASCII. The Python QR
reader reverses Base85 before applying this byte-level contract. Base85 is a QR
presentation encoding, not an additional protocol field.

### Browser/mobile fountain text envelope

The web demo and Meow Capture use this ASCII QR envelope for animated browser
payloads, including Cat Mode:

```text
FOUNTAIN:<k_blocks>:<block_size>:<original_length>:<droplet_b64>
```

- Numeric fields are unsigned decimal ASCII.
- `droplet_b64` is RFC 4648 Base64 of the same packed droplet layout above.
- `original_length` is the exact byte length before fountain zero-padding.
- A receiver MUST reject invalid numeric fields, invalid Base64, and
  inconsistent parameters within one session. (Meow Capture validates all
  three numeric fields and drops droplets whose
  `<k_blocks>:<block_size>:<original_length>` header differs from the first
  accepted frame; it does not unpack droplet bytes, so truncation inside
  `droplet_b64` is caught later by the reconstructing decoder.)
- A receiver deduplicates by droplet seed or stable droplet content. A
  reconstructing receiver (web demo) stops when fountain reconstruction
  completes; a collecting receiver (Meow Capture) stops at the
  `ceil(1.5 x k_blocks)` unique-droplet threshold and defers reconstruction
  to the desktop decoder.

For the web demo, reconstructed bytes are an already-encrypted `MEOW:` text
payload. This browser envelope is not a MEOW2/3/4/5 manifest and MUST NOT be
treated as frame 0 of the signed CLI/GIF protocol. It does not disable or
downgrade mandatory manifest signing for core artifacts.

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
- **Ratchet AAD mismatch:** hard fail, abort entire decode (no partial plaintext leak).
- **Ratchet sequence number invalid:** hard fail.
- **Ratchet key commitment tag invalid:** hard fail.

All failures must be **safe and boring**: no partial plaintext and no detailed oracle messages.

---

## 9.1 Ratchet Hard Invariants (MSR v1.2)

The per-frame symmetric ratchet enforces the following invariants.
Violation of any invariant is a security bug and MUST abort decoding.

1. **No chain key reuse after ratchet forward.**
   `chain_key[i]` is zeroized immediately after deriving `chain_key[i+1]`
   and `message_key[i]`. There is no API to retrieve a previous chain key.

2. **Fail-closed on AAD / sequence mismatch.**
   If AAD verification fails or the frame index does not match the
   expected ratchet position (after skip-cache lookup), the entire
   decode MUST abort. No partial plaintext is emitted.

3. **No rollback to previous chain state.**
   The decoder maintains a consumed-set of frame indices. Re-processing
   an already-consumed index raises `ValueError`. The ratchet state
   machine has no backward transition.

4. **Key commitment prevents invisible salamanders.**
   Each frame includes an HMAC-SHA256 commitment tag (16 bytes).
   The decoder verifies the commitment BEFORE trusting decrypted output.

5. **Skip cache bounded (DoS protection).**
   At most `MAX_SKIP_KEYS = 2000` cached message keys. Exceeding this
   bound raises `ValueError` (attacker cannot force unbounded memory).

See `meow_decoder/ratchet.py` and `tests/test_ratchet.py` for implementation.
See `tests/security/test_ratchet_forward_secrecy.py` for property-based tests.

---

## 10. Version Compatibility

- Decoders MUST accept MEOW2 for legacy password‑only files.
- Encoders MUST emit MEOW3+ for new files.
- PQ hybrid uses PQ ciphertext field; if absent, decoder MUST treat as non‑PQ.

---

## 11. MEOW5/MEOW4 Post‑Quantum PQXDH Hybrid Mode

### 11.1 KEM Algorithm
- **MEOW5 (default):** ML‑KEM‑768 (FIPS 203 / Kyber768).
  - Ciphertext: 1088 bytes. Public key: 1184 bytes. Shared secret: 32 bytes.
- **MEOW4 (paranoid):** ML‑KEM‑1024 (FIPS 203 / Kyber1024).
  - Ciphertext: 1568 bytes. Public key: 1568 bytes. Shared secret: 32 bytes.

The encode pipeline is fully wired end-to-end:
`encode.py` calls `hybrid_encapsulate(paranoid=False)` for MEOW5 or
`hybrid_encapsulate(paranoid=True)` for MEOW4. When `paranoid=True`,
all KEM operations dispatch to `mlkem1024_*` (not `mlkem768_*`). The decoder
(`decode_gif.py`) calls `hybrid_decapsulate()` when
`manifest.pq_ciphertext` is present.

### 11.2 PQXDH Hybrid Key Derivation (Signal-Style)

```
// Step 1: Classical and quantum shared secrets
classical_ss = X25519(ephemeral_sk, receiver_pk)           // 32 bytes
pq_ss        = ML-KEM-768.Decaps(receiver_sk, kem_ct)      // 32 bytes (or ML-KEM-1024)
combined_ikm = classical_ss || pq_ss                        // 64 bytes

// Step 2: PQXDH two-step HKDF with transcript binding
transcript   = SHA256(
    "meow_pqxdh_transcript_v1" ||
    ephemeral_public_key ||
    receiver_classical_public_key ||
    receiver_pq_public_key ||
    pq_ciphertext
)
PRK          = HMAC-SHA256(salt=0x00*32, IKM=combined_ikm)  // Extract step
shared_secret = HKDF-Expand(PRK, "meow_pqxdh_v1" || transcript, 32)  // Expand step
```

- Classical‑only fallback uses `info = "meow_classical_only_v1"` (single-step HKDF).
- Transcript hash binds ALL exchanged public values into the key derivation.
- The combined secret provides IND‑CCA2 security if **either**
  X25519 or ML‑KEM is unbroken (dual‑PRF combiner via HKDF).

### 11.3 KEM Ciphertext Binding

The KEM ciphertext and ephemeral public key are bound to the manifest
via HMAC‑SHA256 over `MANIFEST_CORE_WITH_OPTIONALS` (§5), which includes
the PQ ciphertext bytes.

```
HMAC_INPUT includes: ... || EPHEMERAL_PK (32) || PQ_CIPHERTEXT (1088 or 1568)
```

> **Note:** The KEM ciphertext is now also bound in AES‑GCM AAD
> via the `pq_ciphertext` parameter of `build_canonical_aad`.  This
> provides defence-in-depth alongside the manifest HMAC.  An attacker
> who substitutes or truncates the KEM ciphertext will fail both HMAC
> and AEAD verification.

### 11.4 Downgrade Prevention

A MEOW5/MEOW4 session **MUST NOT** silently fall back to MEOW3.

- The encoder selects the manifest version before encryption; a MEOW5
  manifest includes the 1088‑byte PQ ciphertext field, and a MEOW4
  manifest includes the 1568‑byte field, making their wire lengths
  unambiguously distinguishable from MEOW3 (147 or 179 bytes).
- Trailing bytes validation: if the mode byte indicates MEOW5 but
  the manifest contains MEOW4-sized data (or vice versa), the
  unconsumed trailing bytes are rejected.
- If the decoder receives a manifest whose length does not include the PQ
  field, it MUST parse it as MEOW3 (not MEOW4/MEOW5).  The expected combined
  key will not match the AEAD tag, causing hard fail.

> **Partial mitigation (2026‑02‑16):** The decoder now calls
> `hybrid_decapsulate()` when PQ ciphertext is present, and raises a
> clear `ValueError("PQ ciphertext present but no receiver keypair")`
> when the keypair is missing.  A future version SHOULD allow the
> receiver to pin to MEOW4 to detect replacement attacks.

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
| Guard‑page memory safety (GB‑001–GB‑008) | Verus | `verus_guarded_buffer.rs` | **Verified** |

> **Note on Verus AEAD proofs:** The file `verus_proofs.rs` contains
> proof *specifications* for AEAD‑001 through AEAD‑004 (nonce uniqueness,
> auth‑gated plaintext, key zeroization, no‑bypass). These are **not**
> machine‑checked Verus proofs — they are doc‑comment annotations
> structured for future verification. The properties are currently
> enforced by Rust's type system (`UniqueNonce`, `AuthenticatedPlaintext`),
> the `zeroize` crate, and comprehensive runtime tests.

---

## 12. References

- Manifest/crypto: meow_decoder/crypto.py
- Frame MAC: meow_decoder/frame_mac.py
- Encode pipeline: meow_decoder/encode.py
- Decode pipeline: meow_decoder/decode_gif.py
