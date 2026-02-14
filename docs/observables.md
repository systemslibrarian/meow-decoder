# Observables & Observational Equivalence

**Owner:** Meow-Decoder Formal Verification Team
**Created:** 2026-02-14
**Spec reference:** [docs/PROTOCOL.md](PROTOCOL.md) §4 Manifest Format, §8 Decoder State Machine

---

## Formal Definition

> **Observational Equivalence:** For all traces $t_1$ (real) and $t_2$ (duress):
> $\text{obs}(t_1) = \text{obs}(t_2) \implies$ no polynomial-time distinguisher has non-negligible advantage.

In the Meow context: an adversary who intercepts the GIF, observes the optical channel,
and knows the protocol specification cannot determine whether the sender used the real
password or the duress password, because the observable outputs are identically distributed.

---

## Observable Table

| Observable | Description | Distinguishable (real vs duress)? | Modelled How? | Formal Artifact |
|-----------|-------------|-----------------------------------|---------------|-----------------|
| **GIF file size** | Total bytes of output animated GIF | ⚠️ Partially — manifest length differs by mode (115–1267 bytes); padding mitigates but not formally guaranteed | TLA+: implicit (frame count); not explicitly modelled for size | [?] Gap: no size-equality invariant |
| **Frame count** | Number of QR frames in GIF | ⚠️ Depends on payload size — real vs decoy may have different sizes | TLA+: `FountainDecodeGuarantee` checks frame sufficiency | [?] Gap: not modelled as indistinguishable |
| **Frame content (QR data)** | Per-frame ciphertext bytes | ✅ No — AES-256-GCM ciphertext is IND-CPA (assumed) | ProVerif: `attacker(real_secret)` query (TRUE) | `meow_encode.pv` query 1a |
| **Manifest bytes** | Frame 0 manifest | ⚠️ Duress tag present/absent changes manifest size | ProVerif: manifest bound via AEAD; Tamarin: `diffEquivLemma` | `MeowDuressEquiv.spthy` |
| **HMAC tag** | 32-byte manifest authentication | ✅ No — keyed by password, indistinguishable from random | ProVerif: password secrecy queries | `meow_encode.pv` query 2a/2b |
| **Nonce** | 12-byte random nonce in manifest | ✅ No — fresh random, independent of password | ProVerif: `new n[]:nonce`; TLA+: `NonceNeverReused` | Both |
| **Salt** | 16-byte Argon2id salt | ✅ No — CSPRNG, independent of password | ProVerif: `new s[]:salt` | `meow_encode.pv` |
| **Frame timing** | GIF frame delay (default 100ms) | ✅ No — fixed at encode time, not password-dependent | Not modelled (implementation constant) | N/A |
| **Decryption timing** | Time to produce output | ⚠️ Partially — Argon2id constant, but duress path runs two KDFs | TLA+: not modelled; Python: `equalize_timing()` | `constant_time.py` L125 |
| **Error message** | What decoder outputs on wrong password | ✅ No — constant error for both wrong-real and wrong-duress | ProVerif: `NoOutputOnAuthFailure` | `meow_encode.pv` query 6a |
| **Decoder output** | Plaintext vs decoy file | ✅ No — adversary doesn't see output (air-gap assumption) | Tamarin: `Duress_Never_Outputs_Real`; ProVerif: query 5a | Both |
| **KEM ciphertext** | ML-KEM-1024 encapsulation (MEOW4) | ✅ No — IND-CCA2 assumed per FIPS 203 | ProVerif: `attacker(pq_shared_marker)` | `meow_encode.pv` query 5b |
| **X25519 ephemeral** | Forward secrecy public key | ✅ No — fresh Diffie-Hellman share, no binding to password | ProVerif: `EncoderWithFS` process | `meow_encode.pv` |
| **Streaming chunks** | Per-chunk ciphertext in streaming mode | ✅ No — AES-256-CTR + independent nonce per session | TLA+: `NonceUniqueness`, `EncryptThenMAC` | `MeowStreaming.tla` |
| **MAC tag (streaming)** | HMAC-SHA256 over nonce ‖ ciphertext | ✅ No — HKDF-derived MAC key, indistinguishable from random | TLA+: `DomainSeparation`, `MACCoversAllChunks` | `MeowStreaming.tla` |

---

## Known Gaps in Observational Equivalence

| Gap | Risk | Priority | Mitigation Path |
|-----|------|----------|-----------------|
| **Manifest size varies by mode** | Adversary can distinguish MEOW2 vs MEOW3 vs MEOW4 by manifest length | Medium | Length padding to fixed size per version; model in TLA+ |
| **Frame count leaks payload size** | Larger payloads → more frames (real vs decoy may differ) | Medium | Schrödinger mode pads both payloads to same size |
| **Decryption timing (duress 2× KDF)** | Timing side-channel distinguishes real from duress | Low | `equalize_timing()` in `constant_time.py`; not formally verified |
| **GIF metadata** | File creation timestamp, tool signature | Low | No Meow metadata in GIF; OS-level metadata out of scope |

---

## Failure-Trace Parity

> **Goal:** All authentication-failure paths produce **identical observables**
> regardless of the underlying reason for failure. An adversary observing a
> rejection cannot learn whether the attempt used the wrong real password,
> wrong duress password, a corrupted KEM ciphertext, a downgrade, or a
> truncated manifest.

### Failure-Observable Requirements

| Observable | Required Behaviour | Verified By |
|-----------|-------------------|-------------|
| **Error code** | Identical constant string for all reject paths (`error_auth_failed`) | Tamarin: `Reject_PQ` rules emit `Out('error_auth_failed')`; Python: `AuthenticationError("Authentication failed")` |
| **Timing class** | All reject paths run Argon2id + HMAC-verify before returning | Implementation: timing equalization in `constant_time.py` |
| **Frame count** | Reject produces zero output frames (no success frames emitted) | Tamarin: `PQ_Failure_Uniform_Observable` lemma — reject → ¬DecodedReal ∧ ¬DuressTriggered |
| **Termination** | All reject paths terminate without output | Tamarin: reject rules produce only `Out('error_auth_failed')`, never session state |
| **Retry behaviour** | No retry limit difference between paths | Implementation: decoder always accepts new input after reject |

### Failure Modes Covered

| Failure Mode | Tamarin Rule | Identical Observable |
|-------------|-------------|---------------------|
| Wrong password (neither real nor duress) | `Decode_PQ_WrongPassword` | `Out('error_auth_failed')` |
| Corrupted KEM ciphertext | `Decode_PQ_CorruptKEM` | `Out('error_auth_failed')` |
| Version downgrade (MEOW3 in MEOW4 session) | `Decode_PQ_Downgrade` | `Out('error_auth_failed')` |
| Tampered manifest MAC | Implicit (HMAC verify fails → process halts) | No output (ProVerif: `DecoderAuthenticated` never fires) |
| Tampered frame MAC | Implicit (frame MAC verify fails → process halts) | No output (ProVerif: `AcceptedFrame` never fires) |

### Formal Evidence

1. **Tamarin `PQ_Failure_Uniform_Observable`** ([MeowDuressEquivPQ.spthy](../formal/tamarin/MeowDuressEquivPQ.spthy)):
   Proves that for ALL `Reject_PQ(session, reason)` events, regardless of `reason`,
   neither `DecodedReal_PQ` nor `DuressTriggered_PQ` fires — the session produces
   only the error output and terminates.

2. **Tamarin `PQ_Downgrade_Never_Succeeds`**: Proves that a downgrade attempt
   (sending MEOW3 payload to a MEOW4 session) never leads to acceptance.

3. **ProVerif Query 6a/6b**: Proves no plaintext output without prior authentication.
   Any failure in HMAC/AEAD verification means the process halts before output.

### Gap: Timing Equalization

The implementation uses `constant_time.py::equalize_timing()` to mask timing differences
between success and failure paths. This is NOT formally verified — it relies on:
- Python `time.sleep()` accuracy (~1ms)
- Constant-time HMAC comparison (`secrets.compare_digest`)
- Argon2id running to completion on all paths (including wrong password)

A formal timing model would require a real-time process calculus (e.g., timed CSP),
which is out of scope for the current verification infrastructure.

---

## Tamarin Diff-Equivalence Models

### MEOW3 Model

The base observational equivalence proof is in [`formal/tamarin/MeowDuressEquiv.spthy`](../formal/tamarin/MeowDuressEquiv.spthy):

- **`diffEquivLemma`**: Proves that an adversary cannot distinguish a real-password session from a duress-password session by observing the channel.
- **Scope**: Covers manifest construction, encryption, authentication, output path.
- **Limitations**: Does not cover timing, file size, or frame count (these are out-of-scope for symbolic models).

### MEOW4 PQ Model

The post-quantum duress OE proof is in [`formal/tamarin/MeowDuressEquivPQ.spthy`](../formal/tamarin/MeowDuressEquivPQ.spthy):

- **`diffEquivLemma`**: Observational equivalence under hybrid KEM (X25519 + ML-KEM-1024).
- **Failure-trace rules**: `Decode_PQ_WrongPassword`, `Decode_PQ_CorruptKEM`, `Decode_PQ_Downgrade` — all produce identical `Out('error_auth_failed')`.
- **KEM integrity**: `PQ_KEM_Ct_Integrity` — decoder accepted same KEM ct encoder sent.

### Verified Properties (Tamarin — Combined)

| Lemma | Property | Model | Status |
|-------|----------|-------|--------|
| `diffEquivLemma` | OE (real ≈ duress) | MEOW3 | Proved |
| `Duress_Never_Outputs_Real` | Duress → no real plaintext | MEOW3 | Proved |
| `Real_Never_Triggers_Duress` | Real → no duress action | MEOW3 | Proved |
| `Real_Password_Secret` | Real password not leaked | MEOW3 | Proved |
| `Duress_Password_Secret` | Duress password not leaked | MEOW3 | Proved |
| `Real_Secret_Confidentiality` | Plaintext confidentiality | MEOW3 | Proved |
| `RealPath_trace` | Sanity (real path executable) | MEOW3 | Proved |
| `DuressPath_trace` | Sanity (duress path executable) | MEOW3 | Proved |
| `diffEquivLemma` | OE (real ≈ duress) under hybrid KEM | MEOW4 | CI-Docker |
| `PQ_Duress_Never_Outputs_Real` | Duress → no real plaintext | MEOW4 | CI-Docker |
| `PQ_Real_Never_Triggers_Duress` | Real → no duress action | MEOW4 | CI-Docker |
| `PQ_KEM_Ct_Integrity` | KEM ct matches sent ct | MEOW4 | CI-Docker |
| `PQ_Failure_Uniform_Observable` | All rejects → same observable | MEOW4 | CI-Docker |
| `PQ_Downgrade_Never_Succeeds` | MEOW3→MEOW4 downgrade blocked | MEOW4 | CI-Docker |

---

## References

- Bellare, M., Canetti, R., Krawczyk, H. "A modular approach to the design and analysis of authentication and key exchange protocols." STOC 1998.
- Cachin, C. "An Information-Theoretic Model for Steganography." Information Hiding 1998.
- [docs/PROTOCOL.md](PROTOCOL.md) — Wire format and state machines.
- [docs/SCHRODINGER.md](SCHRODINGER.md) — Quantum plausible deniability theory.
- [docs/THREAT_MODEL.md](THREAT_MODEL.md) — Attack surface and adversary capabilities.
