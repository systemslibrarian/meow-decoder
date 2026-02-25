# Production Minimal (PROD_MIN) Profile

**Version:** 1.0.0
**Status:** Normative — all encode output MUST conform to this profile.

---

## Profile Definition

| Field                | Value                                      |
|----------------------|--------------------------------------------|
| `crypto_profile`     | `"PROD_MIN"`                               |
| Manifest version     | MEOW2 (password-only) or MEOW3 (forward secrecy with X25519) |
| Cipher               | AES-256-GCM                                |
| KDF                  | Argon2id (512 MiB / 20 iterations / 4 threads) |
| HMAC                 | HMAC-SHA256 with domain-separated key      |
| Backend              | Rust (`crypto_core`) — **required**        |
| Frame MACs           | ON (HMAC-SHA256 per frame)                 |
| Per-frame ratchet    | ON when `enable_ratchet=True` (optional)   |
| Post-quantum         | OFF (use `--pq` for experimental MEOW5/MEOW4 PQ hybrid) |
| Hardware keys        | OPTIONAL (HSM/TPM/YubiKey), not default    |
| Steganography        | NOT part of PROD_MIN                       |
| Schrödinger mode     | NOT part of PROD_MIN                       |

## What PROD_MIN Means

1. **Encoder** always writes `crypto_profile: "PROD_MIN"` into metadata (frame 0 / manifest wrapper).
2. **Decoder** rejects manifests with missing or unknown `crypto_profile` unless `--allow-experimental` is passed.
3. The Rust crypto backend is mandatory — no Python-native crypto fallback.
4. All frame MACs are computed and verified (fail-closed on mismatch).
5. HMAC verification is mandatory before any decryption.
6. No silent downgrades: if PQ mode is requested but unavailable, fail hard.

## Experimental Profiles

| Profile                      | Description                     | Requires flag          |
|------------------------------|---------------------------------|------------------------|
| `hybrid_pq_experimental`     | ML-KEM-768/1024 + X25519       | `--pq` or `--pq-paranoid` flag required |

PQ hybrid mode is **opt-in** via explicit `--pq` CLI flag. The encoder writes MEOW2/MEOW3 (PROD_MIN) by default.

The `hybrid_pq_experimental` label reflects that PQ crypto integration has NOT been
externally audited — it does not mean PQ is unavailable or broken.

**Important:** PQ mode uses algorithms that are standardized (FIPS 203) but the
integration in this project has NOT been independently audited. Use at your own risk.

## Decoder Compatibility

The decoder MAY accept older manifest versions (MEOW2, MEOW3, MEOW4) for backward
compatibility. However:
- Missing `crypto_profile` on legacy files triggers a warning but is accepted
  with `--allow-legacy` (to avoid breaking existing encrypted files).
- The decoder MUST still verify HMAC and frame MACs on all accepted manifests.
- No unauthenticated plaintext is ever released.

## What Is NOT PROD_MIN

The following features exist in the codebase but are quarantined in
`meow_decoder/experimental/` or gated behind explicit flags:

- Multi-mode steganography (ninja, prowling, cat-eyes-blink, logo-eyes)
- Schrödinger dual-secret mode
- Dead-man's switch
- Alternative PQ providers
- Debug/verbose encode variants
- Mobile bridge protocols (`meow_decoder.mobile_bridge`)
- Capture merge CLI (`meow_decoder.merge`) — safe to use standalone, but not auto-imported by production encode/decode
- Clowder multi-device streaming

These features MUST NOT be imported by production code without explicit user opt-in.
